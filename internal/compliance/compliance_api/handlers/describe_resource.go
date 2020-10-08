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
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

// DescribeResource returns all pass/fail information needed for the resource overview page.
func (API) DescribeResource(input *models.DescribeResourceInput) *models.LambdaOutput {
	var err error
	input.ResourceID, err = url.QueryUnescape(input.ResourceID)
	if err != nil {
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusBadRequest}
	}

	queryInput, err := buildDescribeResourceQuery(input.ResourceID)
	if err != nil {
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	detail, err := policyResourceDetail(queryInput, input.Page, input.PageSize, input.Severity, input.Status, input.Suppressed)
	if err != nil {
		return &models.LambdaOutput{ErrorMessage: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return &models.LambdaOutput{Body: detail, StatusCode: http.StatusOK}
}

func buildDescribeResourceQuery(resourceID string) (*dynamodb.QueryInput, error) {
	keyCondition := expression.Key("resourceId").Equal(expression.Value(resourceID))
	// We can't do any additional filtering here because we need to include global totals
	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		zap.L().Error("expression.Build failed", zap.Error(err))
		return nil, err
	}

	return &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		KeyConditionExpression:    expr.KeyCondition(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}
