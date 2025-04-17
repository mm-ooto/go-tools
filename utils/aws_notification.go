package utils

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/sns"
)

type AwsConfig struct {
	Region      string // AWS区域
	AccessKeyId string // AWS访问密钥ID
	SecretKey   string // AWS访问密钥
}

// EmailData 邮件
type EmailData struct {
	Recipient string // 接收者
	Body      string // 正文
	Subject   string // 主题
	Sender    string // 发送者
	CharSet   string // 编码
}

type EmailConfig struct {
	AwsConfig *AwsConfig
	EmailData *EmailData
}

// NewEmailService 新建一个邮件服务
func NewEmailService(ec *AwsConfig) *EmailConfig {
	return &EmailConfig{
		AwsConfig: ec,
		EmailData: nil,
	}
}

// SendEmail 发送邮件信息
func (ec *EmailConfig) SendEmail(ecData *EmailData) error {
	sess, err := newAwsSession(ec.AwsConfig.Region, ec.AwsConfig.AccessKeyId, ec.AwsConfig.SecretKey)
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %v", err)
	}

	svc := ses.New(sess)
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{aws.String(ecData.Recipient)},
			ToAddresses: []*string{aws.String(ecData.Recipient)},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String(ecData.CharSet),
					Data:    aws.String(ecData.Body),
				},
				Text: &ses.Content{
					Charset: aws.String(ecData.CharSet),
					Data:    aws.String(ecData.Body),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(ecData.CharSet),
				Data:    aws.String(ecData.Subject), // 使用正确的主题
			},
		},
		Source: aws.String(ecData.Sender),
	}

	if _, err := svc.SendEmail(input); err != nil {
		return fmt.Errorf("failed to send email to %s: %v", ecData.Recipient, err)
	}
	return nil
}

// SnsData 短信
type SnsData struct {
	PhoneNumber string // 接收者电话号码
	Body        string // 正文
}

type SnsConfig struct {
	AwsConfig *AwsConfig
	SnsData   *SnsData
}

// NewSnsService 新建一个短信通知服务
func NewSnsService(ec *AwsConfig) *SnsConfig {
	return &SnsConfig{
		AwsConfig: ec,
	}
}

// SendSns 发送短信通知
func (sc *SnsConfig) SendSns(snsData *SnsData) error {
	sess, err := newAwsSession(sc.AwsConfig.Region, sc.AwsConfig.AccessKeyId, sc.AwsConfig.SecretKey)
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %v", err)
	}

	svc := sns.New(sess)
	input := &sns.PublishInput{
		Message:     aws.String(snsData.Body),
		PhoneNumber: aws.String(snsData.PhoneNumber),
	}

	if _, err = svc.Publish(input); err != nil {
		return fmt.Errorf("failed to send SMS to %s: %v", snsData.PhoneNumber, err)
	}
	return nil
}

// newAwsSession 创建AWS会话的公共方法
func newAwsSession(region string, accessKeyId string, secretKey string) (*session.Session, error) {
	cfgs := &aws.Config{
		Region: aws.String(region),
	}
	if accessKeyId != "" && secretKey != "" {
		cfgs.Credentials = credentials.NewStaticCredentials(accessKeyId, secretKey, "")
	}
	return session.NewSession(cfgs)
}
