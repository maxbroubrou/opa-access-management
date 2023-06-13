package policy

default allow = false

# Allow admins to do anything
allow {
	user_is_admin
}

# Allow bob to do anything
#allow {
#	input.user == "bob"
#}

# Allow the action if the user is granted permission to perform the action.
allow {
	# Find permissions for the user.
	some permission
	user_is_granted[permission]

	# Check if the permission permits the action.
	input.action == permission.action
	input.type == permission.type

	# unless user location is outside US
	country := data.users[input.user].location.country
	country == "US"
}

# user_is_admin is true if...
user_is_admin {
	# for some `i`...
	some i

	# "admin" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "admin"
}

# user_is_viewer is true if...
user_is_viewer {
	# for some `i`...
	some i

	# "viewer" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "viewer"
}

# user_is_guest is true if...
user_is_guest {
	# for some `i`...
	some i

	# "guest" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "guest"
}


# user_is_granted is a set of permissions for the user identified in the request.
# The `permission` will be contained if the set `user_is_granted` for every...
user_is_granted[permission] {
	some i, j

	# `role` assigned an element of the user_roles for this user...
	role := data.users[input.user].roles[i]

	# `permission` assigned a single permission from the permissions list for 'role'...
	permission := data.role_permissions[role][j]
}
