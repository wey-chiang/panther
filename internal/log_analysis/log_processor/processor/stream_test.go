package processor

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	defaultTestTimeLimit = time.Second * 2
)

var (
	snsMessage = `{}` // empty JSON is fine

	streamTestReceiveMessageOutput = &sqs.ReceiveMessageOutput{
		Messages: []*sqs.Message{
			{
				Body:          aws.String(snsMessage),
				ReceiptHandle: aws.String("testMessageHandle"),
			},
		},
	}

	streamTestMessagesAboveThreshold = &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages:        aws.String("200"),
			sqs.QueueAttributeNameApproximateNumberOfMessagesDelayed: aws.String("0"),
		},
	}
	streamTestMessagesBelowThreshold = &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages:        aws.String("0"),
			sqs.QueueAttributeNameApproximateNumberOfMessagesDelayed: aws.String("0"),
		},
	}
)

func init() {
	// set these once at start of test
	common.Config.AwsLambdaFunctionMemorySize = 1024
	common.Config.SqsQueueURL = "https://fakesqsurl"
}

func TestDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	assert.True(t, isProcessingTimeRemaining(deadline), "before deadline")
	time.Sleep(time.Second)
	assert.False(t, isProcessingTimeRemaining(deadline), "after deadline")
}

func TestProcessingDeadline(t *testing.T) {
	diff := time.Second
	now := time.Now()
	deadline := now.Add(diff)
	processingDeadlineTime := processingDeadlineTime(deadline)
	assert.True(t, processingDeadlineTime.Before(deadline), "before deadline")
	// FIXME: make better
	assert.True(t,
		// these should be very close
		diff/processingTimeLimitDivisor-deadline.Sub(processingDeadlineTime) < time.Second/100,
		"correct")
}

func TestStreamEvents(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one is below threshold, which breaks the loop
	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesBelowThreshold, nil).Once()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, streamTestDeadline,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsProcessingTimeLimitExceeded(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	deadline := streamTestDeadline.Add(-defaultTestTimeLimit * 2) // set in the past so code exits immediately

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, deadline,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, 0, sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsReadEventError(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()

	_, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, streamTestDeadline,
		noopProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "readEventError", err.Error())
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsProcessError(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	deadline := streamTestDeadline.Add(-defaultTestTimeLimit * 2) // set in the past so code exits immediately

	_, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, deadline,
		failProcessorFunc, noopReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error())
}

func TestStreamEventsProcessErrorAndReadEventError(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()

	_, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, streamTestDeadline,
		failProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error()) // expect the processError NOT readEventError
}

func TestStreamEventsReceiveSQSError(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	// this one fails
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{},
		fmt.Errorf("receiveError")).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, streamTestDeadline,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	assert.Error(t, err)
	assert.Equal(t, 0, sqsMessageCount)
	assert.Equal(t, "failure receiving messages from https://fakesqsurl: receiveError", err.Error())
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsDeleteSQSError(t *testing.T) {
	streamTestSqsClient, streamTestLambdaClient, streamTestDeadline := initTest()

	logs := mockLogger()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one is below threshold, which breaks the loop
	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesBelowThreshold, nil).Once()
	// this one fails
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{
		Failed:     []*sqs.BatchResultErrorEntry{{}},
		Successful: []*sqs.DeleteMessageBatchResultEntry{},
	}, fmt.Errorf("deleteError")).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestLambdaClient, streamTestDeadline,
		noopProcessorFunc, noopReadSnsMessagesFunc)

	// keep sure we get error logging
	actualLogs := logs.AllUntimed()
	expectedLogs := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{
				Level:   zapcore.ErrorLevel,
				Message: "failure deleting sqs messages",
			},
			Context: []zapcore.Field{
				zap.String("guidance", "failed messages will be reprocessed"),
				zap.String("queueURL", common.Config.SqsQueueURL),
				zap.Int("numberOfFailedMessages", 1),
				zap.Int("numberOfSuccessfulMessages", 0),
				zap.Error(errors.New("deleteError")),
			},
		},
	}

	assert.NoError(t, err) // this does not cause failure of the lambda
	assert.Equal(t, len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	assert.Equal(t, len(expectedLogs), len(actualLogs))
	for i := range expectedLogs {
		assertLogEqual(t, expectedLogs[i], actualLogs[i])
	}
	streamTestSqsClient.AssertExpectations(t)
}

// FIXME: add scaleup test

// FIXME: add gradient test

func initTest() (streamTestSqsClient *testutils.SqsMock, streamTestLambdaClient *testutils.LambdaMock, streamTestDeadline time.Time) {
	// new mocks for each test
	streamTestSqsClient = &testutils.SqsMock{}
	streamTestLambdaClient = &testutils.LambdaMock{}
	streamTestDeadline = time.Now().Add(defaultTestTimeLimit)
	return
}

func noopProcessorFunc(streamChan <-chan *common.DataStream, _ destinations.Destination) error {
	// drain channel
	for range streamChan {

	}
	return nil
}

// simulates error processing the data in a file
func failProcessorFunc(_ <-chan *common.DataStream, _ destinations.Destination) error {
	return fmt.Errorf("processError")
}

func noopReadSnsMessagesFunc(messages []string) ([]*common.DataStream, error) {
	return make([]*common.DataStream, len(messages)), nil
}

// simulated error parsing sqs message or reading s3 object
func failReadSnsMessagesFunc(_ []string) ([]*common.DataStream, error) {
	return nil, fmt.Errorf("readEventError")
}
