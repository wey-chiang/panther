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

import * as Types from '../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAvailableDestinationsBasicVariables = {};

export type ListAvailableDestinationsBasic = {
  destinations?: Types.Maybe<
    Array<Types.Maybe<Pick<Types.Destination, 'outputId' | 'outputType' | 'displayName'>>>
  >;
};

export const ListAvailableDestinationsBasicDocument = gql`
  query ListAvailableDestinationsBasic {
    destinations {
      outputId
      outputType
      displayName
    }
  }
`;

/**
 * __useListAvailableDestinationsBasic__
 *
 * To run a query within a React component, call `useListAvailableDestinationsBasic` and pass it any options that fit your needs.
 * When your component renders, `useListAvailableDestinationsBasic` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAvailableDestinationsBasic({
 *   variables: {
 *   },
 * });
 */
export function useListAvailableDestinationsBasic(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListAvailableDestinationsBasic,
    ListAvailableDestinationsBasicVariables
  >
) {
  return ApolloReactHooks.useQuery<
    ListAvailableDestinationsBasic,
    ListAvailableDestinationsBasicVariables
  >(ListAvailableDestinationsBasicDocument, baseOptions);
}
export function useListAvailableDestinationsBasicLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListAvailableDestinationsBasic,
    ListAvailableDestinationsBasicVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    ListAvailableDestinationsBasic,
    ListAvailableDestinationsBasicVariables
  >(ListAvailableDestinationsBasicDocument, baseOptions);
}
export type ListAvailableDestinationsBasicHookResult = ReturnType<
  typeof useListAvailableDestinationsBasic
>;
export type ListAvailableDestinationsBasicLazyQueryHookResult = ReturnType<
  typeof useListAvailableDestinationsBasicLazyQuery
>;
export type ListAvailableDestinationsBasicQueryResult = ApolloReactCommon.QueryResult<
  ListAvailableDestinationsBasic,
  ListAvailableDestinationsBasicVariables
>;
export function mockListAvailableDestinationsBasic({
  data,
  variables,
  errors,
}: {
  data: ListAvailableDestinationsBasic;
  variables?: ListAvailableDestinationsBasicVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListAvailableDestinationsBasicDocument, variables },
    result: { data, errors },
  };
}
