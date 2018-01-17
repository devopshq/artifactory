# Artifactory Query Language

Library supported [Artifactory-AQL](https://www.jfrog.com/confluence/display/RTF/Artifactory+Query+Language)

```python
from artifactory import ArtifactoryPath
aql = ArtifactoryPath( "http://my-artifactory/artifactory") # path to artifactory, NO repo

# dict support
# Send query: 
# items.find({"repo": "myrepo"})
artifacts = aql.aql("items.find", {"repo": "myrepo"}) 

# list support. 
# Send query: 
# items.find().include("name", "repo")
artifacts = aql.aql("items.find()", ".include", ["name", "repo"]) 

#  support complex query
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
args = ["items.find", {"$and": [
    {
        "repo": {"$eq": "repo"}
    },
    {
        "$or": [
            {"path": {"$match": "*path1"}},
            {"path": {"$match": "*path2"}},
        ]
    },
]
}]

# artifacts_list contains raw data (list of dict)
# Send query: 
# items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})
artifacts_list = aql.aql(*args) 

# You can convert to pathlib object:
artifact_pathlib = map(aql.from_aql, artifacts_list)
artifact_pathlib_list = list(map(aql.from_aql, artifacts_list))
```
