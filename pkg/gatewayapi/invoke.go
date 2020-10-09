package gatewayapi

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
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

// Invoke a former API gateway proxy Lambda directly.
//
// Unmarshals the response body into output and returns (http status code, error).
// A non-nil error could be caused by:
//     - failure to marshal request / unmarshal response
//     - lambda function failed to invoke (does not exist, insufficient permissions)
//     - lambda function runtime exception (panic, OOM, timeout)
//     - status code is not 2XX
//
// This is similar to genericapi.Invoke and will be obsolete once we consolidate the internal API.
func InvokeLambda(client lambdaiface.LambdaAPI, function string, input, output interface{}) (int, error) {
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("%s: jsoniter.Marshal(input) failed: %s", function, err)
	}

	zap.L().Debug(
		"invoking gateway Lambda function",
		zap.String("name", function), zap.Int("bytes", len(payload)))
	response, err := client.Invoke(
		&lambda.InvokeInput{FunctionName: aws.String(function), Payload: payload})

	// Invocation failed - permission error, function doesn't exist, etc
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("%s: lambda.Invoke() failed: %s", function, err)
	}

	// The Lambda function returned an error.
	// For gateway handlers, this should only happen for a runtime exception: out of memory, timeout, panic, etc
	if response.FunctionError != nil {
		return http.StatusInternalServerError, fmt.Errorf("%s: execution failed: %s", function, response.Payload)
	}

	// All gateway proxies had to return this type for API gateway.
	var result events.APIGatewayProxyResponse
	if err := jsoniter.Unmarshal(response.Payload, &result); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("%s: proxy response could not be parsed: %s", function, response)
	}

	if result.StatusCode < 200 || result.StatusCode >= 300 {
		return result.StatusCode, fmt.Errorf("%s: unsuccessful status code %d: %s",
			function, result.StatusCode, result.Body)
	}

	if output != nil {
		if err := jsoniter.UnmarshalFromString(result.Body, output); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("%s: response could not be parsed into output variable: %s",
				function, err)
		}
	}

	return result.StatusCode, nil
}
