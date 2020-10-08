package handlers

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
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

// GetStatus retrieves a single policy/resource status pair from the Dynamo table.
func (API) GetStatus(input *models.GetStatusInput) *models.LambdaOutput {
	var err error
	input.PolicyID, err = url.QueryUnescape(input.PolicyID)
	if err != nil {
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusBadRequest}
	}
	input.ResourceID, err = url.QueryUnescape(input.ResourceID)
	if err != nil {
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusBadRequest}
	}

	response, err := dynamoClient.GetItem(&dynamodb.GetItemInput{
		Key:       tableKey(input.ResourceID, input.PolicyID),
		TableName: &Env.ComplianceTable,
	})
	if err != nil {
		zap.L().Error("dynamoClient.GetItem failed", zap.Error(err))
		if err != nil {
			return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusInternalServerError}
		}
	}

	if len(response.Item) == 0 {
		return &models.LambdaOutput{Body: "compliance entry not found", StatusCode: http.StatusNotFound}
	}

	var entry models.ComplianceEntry
	if err := dynamodbattribute.UnmarshalMap(response.Item, &entry); err != nil {
		zap.L().Error("dynamodbattribute.UnmarshalMap failed", zap.Error(err))
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return &models.LambdaOutput{Body: entry, StatusCode: http.StatusOK}
}
