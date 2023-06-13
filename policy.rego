package policy

default allow = false

import data.role_permissions
import data.users

# Allow admins to do anything
allow {
	some j
	users[j].name == input.user
	users[j].role == role_permissions[_].role
	users[j].role == "admin"
}

# Allow authorised roles to do actions on resources
allow {
	some i

	#		DEBUG
	# 	    print(contains(role_permissions[1].action,"w")) #false
	# 		print(contains(role_permissions[1].action,"delete")) #true
	#     	print(type_name(role_permissions[1].action)) #string
	#     	print(split(replace(replace(substring(role_permissions[1].action, 1, count(role_permissions[1].action)-2),`"`,""), " ", ""),",")) # ["create", "edit", "delete"]

	# check resource
	role_permissions[i].resource == input.resource

	# check user role
	some j
	users[j].name == input.user
	users[j].role == role_permissions[i].role

	# check action
	action_list := split(replace(replace(substring(role_permissions[i].action, 1, count(role_permissions[i].action) - 2), `"`, ""), " ", ""), ",") #converts role_permissions[i].action from string to list
	some k
	action_list[k] == input.action
}
