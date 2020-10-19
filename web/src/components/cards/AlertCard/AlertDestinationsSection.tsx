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
import groupBy from 'lodash/groupBy';
import uniqBy from 'lodash/uniqBy';
import sortBy from 'lodash/sortBy';
import { Icon, Text, Tooltip } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import GenericItemCard from 'Components/GenericItemCard';
import { useListAvailableDestinationsBasic } from 'Source/graphql/queries/listAvailableDestinationsBasic.generated';
import { DeliveryResponse } from 'Generated/schema';

const getLogo = ({ outputType, outputId }) => {
  const { logo } = DESTINATIONS[outputType];
  return <GenericItemCard.Logo key={outputId} src={logo} />;
};

interface AlertDestinationsSectionProps {
  deliveryResponses: DeliveryResponse[];
}
const AlertDestinationsSection: React.FC<AlertDestinationsSectionProps> = ({
  deliveryResponses,
}) => {
  const { data: availableDestinations, loading, error } = useListAvailableDestinationsBasic();

  if (loading) {
    return null;
  }

  if (error) {
    return (
      <Tooltip content="There was a problem when trying to identify destinations for this alert">
        <Icon type="alert-circle" size="medium" color="blue-400" />
      </Tooltip>
    );
  }

  // Grouping delivery responses by destination
  const destinationsByOutputId = groupBy(deliveryResponses, d => d.outputId);

  const destinationsKeys = Object.keys(destinationsByOutputId);

  const allDestinations = destinationsKeys.map(key => {
    // Finding the outputType for each destinations
    const { outputType } = availableDestinations.destinations.find(d => d.outputId === key);
    return { outputId: key, outputType };
  });

  // Identifying unique destinations by outputType
  const uniqueDestinations = sortBy(uniqBy(allDestinations, 'outputType'), d => d.outputType);

  /*
   * Using unique destinations here so we dont render multiple logo of the same type.
   *  i.e. If an alerts has only 2 different slack destinations will render Slack logo once
   */
  if (allDestinations.length - uniqueDestinations.length > 0) {
    // Limiting rendered destinations logos to 3
    const renderedDestinations = uniqueDestinations.slice(0, 3);
    // Showcasing how many additional destinations exist for this alert
    const numberOfExtraDestinations = allDestinations.length - renderedDestinations.length;
    return (
      <React.Fragment>
        {renderedDestinations.map(getLogo)}
        <Text textAlign="center">{`+ ${numberOfExtraDestinations}`}</Text>
      </React.Fragment>
    );
  }

  return <React.Fragment>{allDestinations.map(getLogo)}</React.Fragment>;
};

export default AlertDestinationsSection;
