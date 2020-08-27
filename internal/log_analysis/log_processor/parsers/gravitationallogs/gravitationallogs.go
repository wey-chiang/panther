package gravitationallogs

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
