import React from 'react';
import {
  buildDetectionTestDefinition,
  buildDetectionTestDefinitionInput,
  buildError,
  buildPolicyDetails,
  buildTestPolicyRecord,
  render,
  fireEvent,
  buildTestPolicyRecordFunctions,
  buildTestRuleSubRecord,
} from 'test-utils';
import { UpdatePolicyInput } from 'Generated/schema';
import { Formik } from 'formik';
import { PolicyFormValues } from '../PolicyForm';
import PolicyFormTestSection from './PolicyFormTestSection';
import { mockTestPolicy } from './graphql/testPolicy.generated';

describe('PolicyFormTestSection', () => {
  it('correctly renders the test results', async () => {
    const policy = buildPolicyDetails({
      tests: [
        buildDetectionTestDefinition({
          expectedResult: true,
          name: 'Test 1',
          resource: '{}',
        }),
        buildDetectionTestDefinition({
          expectedResult: false,
          name: 'Test 2',
          resource: '{}',
        }),
      ],
    });

    const mocks = [
      mockTestPolicy({
        variables: {
          input: {
            body: policy.body,
            resourceTypes: policy.resourceTypes,
            tests: [
              buildDetectionTestDefinitionInput({
                expectedResult: true,
                name: 'Test 1',
                resource: '{}',
              }),
              buildDetectionTestDefinitionInput({
                expectedResult: false,
                name: 'Test 2',
                resource: '{}',
              }),
            ],
          },
        },
        data: {
          testPolicy: {
            results: [
              buildTestPolicyRecord({
                id: 'Test 1',
                name: 'Test 1',
                passed: true,
                functions: buildTestPolicyRecordFunctions({
                  policyFunction: buildTestRuleSubRecord({ error: null }),
                }),
              }),
              buildTestPolicyRecord({
                id: 'Test 2',
                name: 'Test 2',
                passed: false,
                functions: buildTestPolicyRecordFunctions({
                  policyFunction: buildTestRuleSubRecord({
                    error: buildError({ message: 'Not Good' }),
                  }),
                }),
              }),
            ],
          },
        },
      }),
    ];

    const { getByText, findByText } = render(
      <Formik<PolicyFormValues>
        initialValues={policy as Required<UpdatePolicyInput>}
        onSubmit={jest.fn()}
      >
        <PolicyFormTestSection />
      </Formik>,
      { mocks }
    );

    // Run the tests
    fireEvent.click(getByText('Run All'));

    // Initially we should see a loading placeholder
    expect(getByText('Running your tests...')).toBeInTheDocument();

    // One should pass without any other message
    expect(await findByText('PASS')).toBeInTheDocument();

    // The other should fail
    expect(getByText('FAIL')).toBeInTheDocument();
    expect(getByText('Not Good')).toBeInTheDocument();
  });
});
