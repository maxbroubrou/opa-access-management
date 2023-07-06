package policy

import future.keywords.in

import data.Permissions
import data.Resources
import data.UsersTeams

default allow := false

resource_id := id {
	Resources[i].name == input.resource
	id := Resources[i].id
}

resourceTypeId := typeId {
	Resources[i].name == input.resource
	typeId := Resources[i].ResourceTypeId
}

resource_index[id] := attributes {
	some resource in Resources
	id := resource.id
	attributes := object.remove(resource, {"id"})
}

team_index[id] := attributes {
	some team in data.Teams
	id := team.id
	attributes := {} # might not be empty in future?
}

all_ids := {id | team_index[id]} | {id | resource_index[id]}

resource_graph[source] := destinations {
	some source, attributes in object.union(team_index, resource_index)
	destinations := [object.get(attributes, "ownerId", null)]
}

team_owners[team] {
	some team in graph.reachable(resource_graph, {resource_id})
	team_index[team]
}

allow {
	UsersTeams[i].UserId == input.userId
	some val in team_owners
	UsersTeams[i].TeamId == val
	UsersTeams[i].RoleId == Permissions[j].RoleId
	Permissions[j].ResourceTypeId == resourceTypeId
}
