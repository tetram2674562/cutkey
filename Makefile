.PHONY: all compile eunit clean

REBAR=$(shell which rebar || echo ./rebar)

all: compile eunit

compile:
	$(REBAR) compile skip_deps=true

eunit: compile
	$(REBAR) eunit skip_deps=true

clean:
	$(REBAR) clean skip_deps=true
