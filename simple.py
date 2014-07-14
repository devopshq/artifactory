#!/usr/bin/env python

import artifactory

p=artifactory.ArtifactoryPath("http://b/artifactory/c/d.xml")
p1 = p.with_suffix('.txt')

print p1
