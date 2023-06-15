package policy

default allow = false

import data.role_permissions
import data.users

# Allow admins to do anything
allow {
	some j
	users[j].token == input.token
	users[j].role == role_permissions[_].role
	users[j].role == "admin"
}

# Allow authorised roles to do method on resources
allow {
	some i

	#		DEBUG
	# 	    print(contains(role_permissions[1].method,"w")) #false
	# 		print(contains(role_permissions[1].method,"delete")) #true
	#     	print(type_name(role_permissions[1].method)) #string
	#     	print(split(replace(replace(substring(role_permissions[1].method, 1, count(role_permissions[1].method)-2),`"`,""), " ", ""),",")) # ["create", "edit", "delete"]

	# check resource
	role_permissions[i].resource == input.resource

	# check user role
	some j
	users[j].token == input.token
	users[j].role == role_permissions[i].role

	# check method
	method_list := split(replace(replace(substring(role_permissions[i].method, 1, count(role_permissions[i].method) - 2), `"`, ""), " ", ""), ",") #converts role_permissions[i].action from string to list
	some k
	method_list[k] == input.method
}
