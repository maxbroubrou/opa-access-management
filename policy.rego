package policy

import data.Resources
​import data.Permissions
import data.UsersTeams
import future.keywords.in
​
default allow := false
​
sub := payload.sub {
	v := input.token
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
	[_, payload, _] := io.jwt.decode(t)
}
​
resource_details := resource_details {
	t := substring(input.resource, 1, -1)
	resource_details := split(t, "/")
}
​
resourceTypeName := typeName {
	Resources[i].id == resource_details[1]
	typeName := Resources[i].ResourceTypeName
}
​
resource_index[id] := attributes {
	some resource in Resources
	id := resource.id
	attributes := object.remove(resource, {"id"})
}
​
team_index[id] := attributes {
	some team in data.Teams
	id := team.id
	attributes := {}
}
​
resource_graph[source] := destinations {
	some source, attributes in object.union(team_index, resource_index)
	destinations := [object.get(attributes, "ownerId", null)]
}
​
team_owners[team] {
	some team in graph.reachable(resource_graph, {resource_details[1]})
	team_index[team]
}
​
allow {
	# GET or POST /resources
	input.method in ["GET", "POST"]
	count(resource_details) == 1
    
	sub == UsersTeams[i].UserId
	UsersTeams[i].RoleId == Permissions[j].RoleId
	Permissions[j].ResourceTypeName == resource_details[0]
	Permissions[j].action == input.method
}
​
allow {
	# GET or PUT or DELETE /resources/:id
	input.method in ["GET", "PUT", "DELETE"]
	count(resource_details) == 2
​
	# check that userId exists in a team
	sub == UsersTeams[i].UserId
​
	# check that the role of this user has permissions on the resourceType he asks
	UsersTeams[i].RoleId == Permissions[j].RoleId
	Permissions[j].ResourceTypeName == resource_details[0]
​
	# check that the role of this user has permissions to do the action he wants to do
	Permissions[j].action == input.method
​
	# check that the specific resource id belongs to the user team
	some val in team_owners
	UsersTeams[i].TeamId == val
​
	# check that the specific resource asked has well the resourceType indicated in the URL
	Resources[k].id == resource_details[1]
	Resources[k].ResourceTypeName == resource_details[0]
}
