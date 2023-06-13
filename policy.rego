package policy

default allow = false

import data.role_permissions
import data.users

# Allow admins to do anything
allow {
	some j
	users[j].name == input.user
	users[j].role == role_permissions[i].role
	users[j].role == "admin"
}

# Allow authorised roles to do actions on resources
allow {
	some i
    
    #		DEBUG
	#     	print(contains(role_permissions[1].action,"w")) #false
	# 		print(contains(role_permissions[1].action,"delete")) #true
	#     	print(type_name(role_permissions[1].action)) #string

	# check resource
	role_permissions[i].resource == input.resource

	# check action
	contains(role_permissions[i].action, input.action)
	some j

	# check user role
	users[j].name == input.user
	users[j].role == role_permissions[i].role
}
