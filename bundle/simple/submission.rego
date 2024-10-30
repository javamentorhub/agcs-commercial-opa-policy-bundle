package agcs.submission

import rego.v1

# Default deny rule
default allow := false

# Main allow rule that checks if the specified action on a submission is permitted
allow if {
	input.object.type == "submission"
	user := data.users[input.subject.email]

	# Check if the action is allowed based on the user's profile and input object attributes
	action_allowed(user, input.action, input.object.oe, input.object.lob, input.object.region)
}

# Rule to check if a specific action is allowed for the user's profile based on OE, LOB, and Region
action_allowed(user, action, oe, lob, _) if {
	action == "create"
	oe_allowed(user, oe)
	lob_allowed(user, lob)
}

action_allowed(user, action, oe, _, region) if {
	action == "read"
	oe_allowed(user, oe)
	region_allowed(user, region)
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
