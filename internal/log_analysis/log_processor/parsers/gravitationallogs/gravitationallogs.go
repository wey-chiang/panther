package gravitationallogs

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

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"

const LogTypePrefix = "Gravitational"

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.MustBuildGroup(logtypes.ConfigJSON{
	NewEvent: func() interface{} {
		return &TeleportAudit{}
	},
	Desc: logtypes.Desc{
		Name:         LogTypePrefix + ".TeleportAudit",
		Description:  `Teleport logs events like successful user logins along with the metadata like remote IP address, time and the session ID.`,
		ReferenceURL: `https://gravitational.com/teleport/docs/admin-guide/#audit-log`,
	},
})
