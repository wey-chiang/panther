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

import GenericItemCard from 'Components/GenericItemCard';
import { Flex, Link } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import DestinationCardOptions from 'Pages/ListDestinations/DestinationCards/DestinationCardOptions';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import urls from 'Source/urls';

interface DestinationCardProps {
  destination: DestinationFull;
  logo: string;
  children: React.ReactNode;
}

const DestinationCard: React.FC<DestinationCardProps> = ({ destination, logo, children }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      <DestinationCardOptions destination={destination} />
      <GenericItemCard.Body>
        <Link
          as={RRLink}
          to={urls.settings.destinations.edit(destination.outputId)}
          cursor="pointer"
        >
          <GenericItemCard.Heading>{destination.displayName}</GenericItemCard.Heading>
        </Link>
        <GenericItemCard.ValuesGroup>
          {children}
          <Flex ml="auto" mr={0} mt={4} align="flex-end" spacing={2}>
            {destination.defaultForSeverity.map(severity => (
              <SeverityBadge severity={severity} key={severity} />
            ))}
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(DestinationCard);
