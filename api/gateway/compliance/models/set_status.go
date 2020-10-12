// Code generated by go-swagger; DO NOT EDIT.

package models

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

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SetStatus set status
//
// swagger:model SetStatus
type SetStatus struct {

	// error message
	ErrorMessage ErrorMessage `json:"errorMessage,omitempty"`

	// integration Id
	// Required: true
	IntegrationID IntegrationID `json:"integrationId"`

	// policy Id
	// Required: true
	PolicyID PolicyID `json:"policyId"`

	// policy severity
	// Required: true
	PolicySeverity PolicySeverity `json:"policySeverity"`

	// resource Id
	// Required: true
	ResourceID ResourceID `json:"resourceId"`

	// resource type
	// Required: true
	ResourceType ResourceType `json:"resourceType"`

	// status
	// Required: true
	Status Status `json:"status"`

	// suppressed
	// Required: true
	Suppressed Suppressed `json:"suppressed"`
}

// Validate validates this set status
func (m *SetStatus) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateErrorMessage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntegrationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicySeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuppressed(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SetStatus) validateErrorMessage(formats strfmt.Registry) error {

	if swag.IsZero(m.ErrorMessage) { // not required
		return nil
	}

	if err := m.ErrorMessage.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("errorMessage")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validateIntegrationID(formats strfmt.Registry) error {

	if err := m.IntegrationID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("integrationId")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validatePolicyID(formats strfmt.Registry) error {

	if err := m.PolicyID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("policyId")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validatePolicySeverity(formats strfmt.Registry) error {

	if err := m.PolicySeverity.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("policySeverity")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validateResourceID(formats strfmt.Registry) error {

	if err := m.ResourceID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resourceId")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validateResourceType(formats strfmt.Registry) error {

	if err := m.ResourceType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resourceType")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validateStatus(formats strfmt.Registry) error {

	if err := m.Status.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("status")
		}
		return err
	}

	return nil
}

func (m *SetStatus) validateSuppressed(formats strfmt.Registry) error {

	if err := m.Suppressed.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("suppressed")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SetStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SetStatus) UnmarshalBinary(b []byte) error {
	var res SetStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}