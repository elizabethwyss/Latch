# Latch Policy Language

The full grammar of Latch's policy language is implemented in [policy.pegjs](https://github.com/elizabethwyss/Latch/blob/main/policy/policy.pegjs)

The two default Latch policies targeted for npm developers and maintainers are provided in [developer.json](https://github.com/elizabethwyss/Latch/blob/main/policy/developer.json) and [maintainer.json](https://github.com/elizabethwyss/Latch/blob/main/policy/maintainer.json) respectively.

## Examples

### Manifest Attributes

Below is the list of manifest attributes that policies can operate over

```
'metadataRequests'
'metadataMods'
'openRead'
'openWrite'
'filesRead'
'filesWritten'
'filesRenamed'
'filesDeleted'
'filesCreated'
'localHosts'
'localNetworkHosts'
'remoteHosts'
'priveledgedCommands'
'unpriveledgedCommands'
'priveledgedExecFiles'
'unpriveledgedExecFiles'
```

Each attribute can be expressed at the granularity of individual scripts

```
'preinstall'
'install'
'postinstall'
'preuninstall'
'uninstall'
'postuninstall'
```

or they can be combined as so

```
[remoteHosts_preinstall] ~union [remoteHosts_install] ~union [remoteHosts_postinstall] ~union [remoteHosts_preuninstall] ~union [remoteHosts_uninstall] ~union [remoteHosts_postuninstall]
```

### Declarations

Declarations function like variables that can be utilized in policy rules as well as other declarations. They are expressed as a list of strings where the left hand side provides an identifier for the declaration and the right hand side provides a value expressed as set operations and/or boolean operations over manifest attributes, declarations, file path strings, and host ip strings. Strings can additionally be expressed using regular expressions.

```
"declarations": [
"<installTimeFilesRead> = [filesRead_preinstall] ~union [filesRead_install] ~union [filesRead_postinstall]",
"<installTimeFilesWritten> = [filesWritten_preinstall] ~union [filesWritten_install] ~union [filesWritten_postinstall]",
"<installTimeRemoteHosts> = [remoteHosts_preinstall] ~union [remoteHosts_install] ~union [remoteHosts_postinstall]",

"<homeFiles> = '\/home\/user\/*'",

"<filesReadOrWritten> = <installTimeFilesRead> ~union <installTimeFilesWritten>",
...
],
```

### Set Operations

Below is the list of set operations available for use in declarations and policy rules

```
// returns a set
'~union'
'~intersect'
'~subtract'

// returns a boolean
'~anymatches'
'~matchesall'
'~exists' // is the lval an element of the rval?
'~subset' // is the lval a subset of the rval?
```

### Boolean Operations

Below is the list of boolean operations available for use in declarations and policy rules
```
&& // and
|| // or
== // equals
! // not
```

### Policy Rules

Policy rules are expressed as two lists of strings, a warn list and a fail list. Each rule is expressed as a boolean value over manifest attributes, declarations, file path strings, and host ip strings.

```
"rulesFail": [
"<installTimeRemoteHosts> == {}",
...
],

"rulesWarn": [
"<installTimeFilesWritten> ~anymatches <homeFiles>",
...
]
```
