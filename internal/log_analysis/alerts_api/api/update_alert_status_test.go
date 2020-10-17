package api

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

func TestUpdateAlert(t *testing.T) {
	tableMock := &tableMock{}
	alertsDB = tableMock

	alertID1 := aws.String("alertId_1")
	alertID2 := aws.String("alertId_2")
	status := aws.String("")
	userID := aws.String("userId")
	timeNow := time.Now()
	input := &models.UpdateAlertStatusInput{
		AlertIDs: []*string{alertID1, alertID2},
		Status:   status,
		UserID:   userID,
	}
	output := []*table.AlertItem{
		{
			AlertID:           *alertID1,
			Status:            "CLOSED",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
		{
			AlertID:           *alertID2,
			Status:            "CLOSED",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
	}
	expectedSummaries := []*models.AlertSummary{
		{
			AlertID:           alertID1,
			Status:            "CLOSED",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
		{
			AlertID:           alertID2,
			Status:            "CLOSED",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
	}

	tableMock.On("UpdateAlertStatus", input).Return(output, nil).Once()
	result, err := API{}.UpdateAlertStatus(input)
	require.NoError(t, err)

	// Marshal to convert "" to nils and focus on our properties
	resultSummaries := []*models.AlertSummary{
		{
			AlertID:           result[0].AlertID,
			Status:            result[0].Status,
			LastUpdatedBy:     result[0].LastUpdatedBy,
			LastUpdatedByTime: result[0].LastUpdatedByTime,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
		{
			AlertID:           result[1].AlertID,
			Status:            result[1].Status,
			LastUpdatedBy:     result[1].LastUpdatedBy,
			LastUpdatedByTime: result[1].LastUpdatedByTime,
			DeliveryResponses: []*models.DeliveryResponse{},
		},
	}

	assert.Equal(t, expectedSummaries, resultSummaries)
}
