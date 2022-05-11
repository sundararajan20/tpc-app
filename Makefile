MVN_IMG := maven:3.6.3-openjdk-11

app-build:
				$(info *** Building the TPC ONOS app...)
				@mkdir -p target
				@docker run --rm -v ${HOME}/.m2:/root/.m2 -v ${PWD}:/mvn-src -w /mvn-src ${MVN_IMG} mvn clean install
				@ls -1 target/*.oar

