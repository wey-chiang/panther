import React from 'react';
import {
  buildDetectionTestDefinition,
  buildDetectionTestDefinitionInput,
  buildError,
  buildRuleDetails,
  buildTestRuleRecord,
  render,
  fireEvent,
  buildTestRuleRecordFunctions,
  buildTestRuleSubRecord,
} from 'test-utils';
import { UpdateRuleInput } from 'Generated/schema';
import { Formik } from 'formik';
import { RuleFormValues } from '../RuleForm';
import RuleFormTestSection from './RuleFormTestSection';
import { mockTestRule } from './graphql/testRule.generated';

describe('RuleFormTestSection', () => {
  it('correctly renders the test results', async () => {
    const rule = buildRuleDetails({
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
      mockTestRule({
        variables: {
          input: {
            body: rule.body,
            logTypes: rule.logTypes,
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
          testRule: {
            results: [
              buildTestRuleRecord({
                id: 'Test 1',
                name: 'Test 1',
                passed: true,
                error: null,
                functions: buildTestRuleRecordFunctions({
                  ruleFunction: buildTestRuleSubRecord({ output: 'Rule Output 1', error: null }),
                  titleFunction: buildTestRuleSubRecord({ output: 'Title Output 1', error: null }),
                  dedupFunction: buildTestRuleSubRecord({ output: 'Dedup Output 1', error: null }),
                }),
              }),
              buildTestRuleRecord({
                id: 'Test 2',
                name: 'Test 2',
                passed: false,
                error: buildError({ message: 'General Error Message' }),
                functions: buildTestRuleRecordFunctions({
                  ruleFunction: buildTestRuleSubRecord({
                    output: 'Rule Output 2',
                    error: buildError({ message: 'Not Good' }),
                  }),
                  titleFunction: null,
                  dedupFunction: null,
                }),
              }),
            ],
          },
        },
      }),
    ];

    const { getByText, findByText } = render(
      <Formik<RuleFormValues>
        initialValues={rule as Required<UpdateRuleInput>}
        onSubmit={jest.fn()}
      >
        <RuleFormTestSection />
      </Formik>,
      { mocks }
    );

    // Run the tests
    fireEvent.click(getByText('Run All'));

    // Initially we should see a loading placeholder
    expect(getByText('Running your tests...')).toBeInTheDocument();

    // One should pass without any other message
    expect(await findByText('PASS')).toBeInTheDocument();
    expect(getByText('Title Output 1')).toBeInTheDocument();
    expect(getByText('Dedup Output 1')).toBeInTheDocument();

    // The other should fail
    expect(getByText('FAIL')).toBeInTheDocument();
    expect(getByText('Not Good')).toBeInTheDocument();
    expect(getByText('General Error Message')).toBeInTheDocument();
  });
});
