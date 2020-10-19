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
import React from 'react';
import uniqBy from 'lodash/uniqBy';
import intersectionBy from 'lodash/intersectionBy';
import { Destination } from 'Generated/schema';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';

interface UseAlertDestinationsProps {
  alert: AlertSummaryFull;
  destinations: Pick<Destination, 'outputId' | 'outputType' | 'displayName'>[];
}

const useAlertDestinations = ({
  alert,
  destinations,
}: UseAlertDestinationsProps): {
  alertDestinations: Pick<Destination, 'outputType' | 'outputId' | 'displayName'>[];
} => {
  const alertDestinations = React.useMemo(() => {
    if (!alert || !destinations) {
      return [];
    }

    const uniqueDestinations = uniqBy(alert.deliveryResponses, 'outputId');
    return intersectionBy(destinations, uniqueDestinations, d => d.outputId);
  }, [alert, destinations]);

  return React.useMemo(
    () => ({
      alertDestinations,
    }),
    [alertDestinations]
  );
};

export default useAlertDestinations;
