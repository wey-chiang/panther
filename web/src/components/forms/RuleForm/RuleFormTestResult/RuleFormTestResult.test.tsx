import React from 'react';
import {
  buildError,
  buildTestRuleRecord,
  buildTestRuleRecordFunctions,
  buildTestRuleSubRecord,
  render,
} from 'test-utils';
import { ComplianceStatusEnum } from 'Generated/schema';
import RuleFormTestResult from './RuleFormTestResult';

describe('RuleFormTestResult', () => {
  it('shows the name & status of the test', () => {
    const testResult = buildTestRuleRecord();

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.name)).toBeInTheDocument();
    expect(
      getByText(testResult.passed ? ComplianceStatusEnum.Pass : ComplianceStatusEnum.Fail)
    ).toBeInTheDocument();
  });

  it('shows a generic error when it exists', () => {
    const testResult = buildTestRuleRecord({
      functions: {
        ruleFunction: null,
        titleFunction: null,
        dedupFunction: null,
      },
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.error.message)).toBeInTheDocument();
  });

  it('shows a list of all the non-generic errors', () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        ruleFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Rule' }) }),
        titleFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Title' }) }),
        dedupFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Dedup' }) }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.ruleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.titleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.error.message)).toBeInTheDocument();
  });

  it("shows title & dedup outputs when errors don't exist", () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        titleFunction: buildTestRuleSubRecord({ output: 'Title', error: null }),
        dedupFunction: buildTestRuleSubRecord({ output: 'Dedup', error: null }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.titleFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.output)).toBeInTheDocument();
  });

  it('matches the snapshot', () => {
    const testResult = buildTestRuleRecord();

    const { container } = render(<RuleFormTestResult testResult={testResult} />);
    expect(container).toMatchSnapshot();
  });
});
