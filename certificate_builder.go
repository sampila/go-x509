package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

const (
	ECDSA_SHA_256             = "EDCSA_SHA_256"
	RSASSA_PKCS1_V1_5_SHA_256 = "RSASSA_PKCS1_V1_5_SHA_256"
	RSASSA_PKCS1_V1_5_SHA_384 = "RSASSA_PKCS1_V1_5_SHA_384"
	RSASSA_PKCS1_V1_5_SHA_512 = "RSASSA_PKCS1_V1_5_SHA_512"
	RSASSA_PSS_SHA_256        = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384        = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512        = "RSASSA_PSS_SHA_512"
)

// CertBuilder instances for Certificate Builder.
type CertBuilder struct {
	// PublicKey rsa or ecdsa public key generated from client instances.
	PublicKey any

	// ParentCert parent certificate, will use template certificate if not set.
	ParentCert *Certificate

	// TemplateCert template certificate.
	TemplateCert *Certificate

	// keyId AWS KMS Key ID.
	keyId string

	// client instances for sign process.
	client any

	// cert generated certificate.
	cert certificate
}

// New creates certificate builder instances.
func New(template *Certificate, client any, keyId string, publicKey any) (*CertBuilder, error) {
	if template == nil {
		return nil, errors.New("Template certificate can't be nil")
	}

	if _, ok := client.(*kms.KMS); !ok {
		return nil, errors.New("Unsupported client type.")
	}

	if keyId == "" {
		return nil, errors.New("Template certificate can't be nil")
	}

	_, isRSAPublicKey := publicKey.(*rsa.PublicKey)
	_, isEcdsaPublicKey := publicKey.(*ecdsa.PublicKey)
	if !isRSAPublicKey && !isEcdsaPublicKey {
		return nil, errors.New("Unsupported public key type.")
	}

	return &CertBuilder{
		TemplateCert: template,
		ParentCert:   template,
		client:       client,
		keyId:        keyId,
		PublicKey:    publicKey,
	}, nil
}

// Build returns signed certificate bytes data.
func (cb *CertBuilder) Build() ([]byte, error) {
	parentCert := cb.TemplateCert
	if cb.ParentCert != nil {
		parentCert = cb.ParentCert
	}

	switch c := cb.client.(type) {
	case *kms.KMS:
		return buildWithAwsKMS(cb.TemplateCert, parentCert, c, cb.keyId, cb.PublicKey)
	}

	return nil, errors.New("Unsupported client type.")
}

// Verify certificate signature verification using client instances.
func (cb *CertBuilder) Verify() error {
	switch c := cb.client.(type) {
	case *kms.KMS:
		return checkSignatureAwsKMS(getSignatureAlgorithmFromAI(cb.cert.SignatureAlgorithm),
			cb.cert.TBSCertificate.Raw, cb.cert.SignatureValue.Bytes, cb.keyId, c)
	}

	return errors.New("Unsupported client type.")
}

// HashAlgorithm returns supported hash algorithm.
func (cb *CertBuilder) HashAlgorithm() (crypto.Hash, error) {
	awsSignAlgo := getAwsSigningAlgorithmType(cb.TemplateCert.SignatureAlgorithm)
	if awsSignAlgo == "" {
		return 0, errors.New("Unkown signature algorithm")
	}

	switch awsSignAlgo {
	case ECDSA_SHA_256, RSASSA_PKCS1_V1_5_SHA_256, RSASSA_PSS_SHA_256:
		return crypto.SHA256, nil
	case RSASSA_PKCS1_V1_5_SHA_384, RSASSA_PSS_SHA_384:
		return crypto.SHA384, nil
	case RSASSA_PKCS1_V1_5_SHA_512, RSASSA_PSS_SHA_512:
		return crypto.SHA512, nil
	}

	return 0, errors.New("Unsupported signature hash algorithm")
}

func buildWithAwsKMS(template, parent *Certificate, awsKms *kms.KMS, keyId string, publicKey any) ([]byte, error) {
	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	// RFC 5280 Section 4.1.2.2: serial number must positive
	//
	// We _should_ also restrict serials to <= 20 octets, but it turns out a lot of people
	// get this wrong, in part because the encoding can itself alter the length of the
	// serial. For now we accept these non-conformant serials.
	if template.SerialNumber.Sign() == -1 {
		return nil, errors.New("x509: serial number must be positive")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	_, signatureAlgorithm, err := signingParamsForPublicKey(publicKey, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	awsSignAlgo := getAwsSigningAlgorithmType(template.SignatureAlgorithm)
	if awsSignAlgo == "" {
		return nil, errors.New("Unsupported AWS Signing Algorithm.")
	}

	var (
		publicKeyBytes     []byte
		publicKeyAlgorithm pkix.AlgorithmIdentifier
	)

	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	signResult, err := awsKms.Sign(&kms.SignInput{
		KeyId:            aws.String(keyId),
		Message:          tbsCertContents,
		SigningAlgorithm: aws.String(awsSignAlgo),
	})
	if err != nil {
		return nil, err
	}

	signature := signResult.Signature

	signedCert, err := asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}

// checkSignatureAwsKMS verifies that signature is a valid signature over `Verify` API for KMS.
func checkSignatureAwsKMS(algo SignatureAlgorithm, signed, signature []byte, keyId string, awsKms *kms.KMS) (err error) {
	awsSignAlgo := getAwsSigningAlgorithmType(algo)
	if awsSignAlgo == "" {
		return errors.New("Unsupported AWS Signing Algorithm.")
	}

	verifyResp, err := awsKms.Verify(&kms.VerifyInput{
		KeyId:            aws.String(keyId),
		Message:          signed,
		Signature:        signature,
		SigningAlgorithm: aws.String(awsSignAlgo),
	})
	if err != nil {
		return err
	}

	if *verifyResp.SignatureValid {
		return nil
	}

	return errors.New("Invalid signature.")
}

// getAwsSigningAlgorithmType returns aws supported sign algorithm string.
func getAwsSigningAlgorithmType(sigAlgo SignatureAlgorithm) string {
	switch sigAlgo {
	case SHA256WithRSA:
		return "RSASSA_PKCS1_V1_5_SHA_256"
	case SHA384WithRSA:
		return "RSASSA_PKCS1_V1_5_SHA_384"
	case SHA512WithRSA:
		return "RSASSA_PKCS1_V1_5_SHA_512"
	case SHA256WithRSAPSS:
		return "RSASSA_PSS_SHA_256"
	case SHA384WithRSAPSS:
		return "RSASSA_PSS_SHA_384"
	case SHA512WithRSAPSS:
		return "RSASSA_PSS_SHA_512"
	}

	return ""
}
