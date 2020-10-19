import React from 'react';
import { Alert, Flex, Card } from 'pouncejs';
import { DetectionTestDefinition } from 'Generated/schema';
import { useFormikContext } from 'formik';
import { RuleFormValues } from 'Components/forms/RuleForm';
import { BaseRuleFormTestSection } from 'Components/forms/BaseRuleForm';
import { extractErrorMessage } from 'Helpers/utils';
import { useTestRule } from './graphql/testRule.generated';
import RuleFormTestResult from '../RuleFormTestResult';

const RuleFormTestSection: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const {
    values: { logTypes, body },
  } = useFormikContext<RuleFormValues>();

  // Load the mutation that will perform the policy testing but we are not yet populating it with
  // the variables since we'll do that on "click" - time
  // prettier-ignore
  const [testRule, { error, loading, data }] = useTestRule();

  // Helper function where the only thing parameterised is the array of tests to submit to the server
  // This helps us reduce the amount of code we write when the only thing changing is the number of
  // tests to run
  const runTests = React.useCallback(
    (testsToRun: DetectionTestDefinition[]) => {
      testRule({
        variables: {
          input: {
            body,
            logTypes,
            tests: testsToRun,
          },
        },
      });
    },
    [body, logTypes]
  );
  return (
    <BaseRuleFormTestSection
      runTests={runTests}
      renderTestResults={
        <React.Fragment>
          {error && (
            <Alert
              variant="error"
              title="Internal error during testing"
              description={
                extractErrorMessage(error) ||
                "An unknown error occured and we couldn't run your tests"
              }
            />
          )}
          {loading && (
            <Card fontSize="medium" fontWeight="medium" p={4}>
              Running your tests...
            </Card>
          )}
          {data && (
            <Flex direction="column" spacing={4}>
              {data.testRule.results.map(testResult => (
                <RuleFormTestResult key={testResult.id} testResult={testResult} />
              ))}
            </Flex>
          )}
        </React.Fragment>
      }
    />
  );
};

export default RuleFormTestSection;
