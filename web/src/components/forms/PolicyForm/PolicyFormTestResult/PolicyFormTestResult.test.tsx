import React from 'react';
import { buildTestPolicyRecord, render } from 'test-utils';
import { ComplianceStatusEnum } from 'Generated/schema';
import PolicyFormTestResult from './PolicyFormTestResult';

describe('PolicyFormTestResult', () => {
  it('shows the necessary information', () => {
    const testResult = buildTestPolicyRecord();

    const { getByText } = render(<PolicyFormTestResult testResult={testResult} />);
    expect(getByText(testResult.name)).toBeInTheDocument();
    expect(getByText(testResult.error.message)).toBeInTheDocument();
    expect(
      getByText(testResult.passed ? ComplianceStatusEnum.Pass : ComplianceStatusEnum.Fail)
    ).toBeInTheDocument();
  });

  it('matches the snapshot', () => {
    const testResult = buildTestPolicyRecord();

    const { container } = render(<PolicyFormTestResult testResult={testResult} />);
    expect(container).toMatchSnapshot();
  });
});
