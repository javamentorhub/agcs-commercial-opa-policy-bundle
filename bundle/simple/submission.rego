package agcs.submission

import rego.v1

default create_allow := false

default read_allow := false

# Main allow rule that checks if the specified action on a submission is permitted
create_allow if {
	input_oe := input.action.fields_input_action_permission.oe
	input_lob := input.action.fields_input_action_permission.lob
	user := data.users[input.subject.email]
	input.action.name == "create"
	some role in user.role
	role.position == "uw"
	oe_allowed(user, input_oe)
	lob_allowed(user, input_lob)
}

# Main allow rule that checks if the specified action on a submission is permitted
read_allow if {
	input_region := input.action.fields_input_action_permission.region
	input_lob := input.action.fields_input_action_permission.lob
	user := data.users[input.subject.email]
	input.action.name == "read"
	some role in user.role
	role.position == "uw"
	region_allowed(user, input_region)
	lob_allowed(user, input_lob)
}

# Check if the specified OE is within the user's allowed OEs
oe_allowed(user, oe) if {
	# user_allowed_oe := user.allowed_oes[_]
	some user_allowed_oe in user.allowed_oes
	oe == user_allowed_oe
}

# Check if the specified LOB is within the user's allowed LOBs
lob_allowed(user, lob) if {
	# user_allowed_lob := user.allowed_lobs[_]
	some user_allowed_lob in user.allowed_lobs
	lob == user_allowed_lob
}

# Check if the specified Region is within the user's allowed Regions
region_allowed(user, region) if {
	# user_allowed_region := user.allowed_regions[_]
	some user_allowed_region in user.allowed_regions
	region == user_allowed_region
}

default create_error_message := "Action not allowed!"

create_error_message := "" if {
	create_allow
}

default create_error_type := "action_error"

create_error_type := "" if {
	create_error_message == ""
}

create_output := {
	"result": create_allow,
	"error_message": create_error_message,
	"error_type": create_error_type,
}

default read_error_message := "Action not allowed!"

read_error_message := "" if {
	read_allow
}

default read_error_type := "action_error"

read_error_type := "" if {
	read_error_message == ""
}

read_output := {
	"result": read_allow,
	"error_message": read_error_message,
	"error_type": read_error_type,
}


