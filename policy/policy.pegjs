{
    let thisParser = this;

    function resolveSymbol(parser, sym){
        let prop = sym.split('_')[0];
        let script = sym.split('_')[1];
        return (parser.symbols || {})[script][prop];
    }

    function resolveId(parser, id){
        return (parser.ids || {})[id];
    }

    function resolveFileRegex(parser, id){
        return (parser.fileRegs || {})[id];
    }

    function addSymbol(parser, sym, val){
        parser.symbols[sym] = val;
    }

    function addId(parser, id, val){
        parser.ids[id] = val;
    }

    function addFileRegex(parser, id, reg){
        parser.fileRegs[id] = new RegExp(reg);
    }

    function UNION(setA, setB) {
        let _union = new Set(setA);
        for (let elem of setB) {
            _union.add(elem);
        }
        return _union;
    }

    function INTERSECT(setA, setB) {
        let _intersection = new Set();
        for (let elem of setB) {
            if (setA.has(elem)) {
                _intersection.add(elem);
            }
        }
        return _intersection;
    }

    function SUBTRACT(setA, setB) {
        let _difference = new Set(setA);
        for (let elem of setB) {
            _difference.delete(elem);
        }
        return _difference;
    }

    function EQUALS(left, right){
        if(left.size != right.size) return false;
        else{
            for(let elem of left){
                if(!right.has(elem)){
                    return false;
                }
            }
            return true;
        }
    }

    function SUBSET(left, right){ //is left a subset of right
        if(left.size > right.size) return false;
        else{
            for(let elem of left){
                if(!right.has(elem)){
                    return false;
                }
            }
            return true;
        }
    }

    function EXISTS(elem, set){
        return set.has(elem);
    }

    function setAllMatches(set, fileRegList){
        for(let file of set){
            let allMatch = true;
            for(let fileid of fileRegList){
                let fileReg = resolveFileRegex(thisParser, fileid);
                let match = file.match(fileReg);
                if(!((match) ? (match.index == 0 ? (match[0].length == file.length ? true : false): false) : false)){
                    allMatch = false;
                    break;
                }
            }
            if(!allMatch) return false;
        }
        return true;
    }

    function setAnyMatches(set, fileRegList){
        //console.log(fileRegList)
        //console.log(set)
        for(let file of set){
            let allMatch = true;
            for(let fileid of fileRegList){
                let fileReg = resolveFileRegex(thisParser, fileid);
                let match = file.match(fileReg);
                //if(match) console.log(file, fileReg, match.input, match[0], ((match) ? (match.index == 0 ? (match[0].length == file.length ? true : false): false) : false))
                //if(match) console.log(match)
                if(!((match) ? (match.index == 0 ? (match[0].length == file.length ? true : false): false) : false)){
                    allMatch = false;
                    break;
                }
            }
            if(allMatch) {return true;}
        }
        return false;
    }
}

start "start"
  = ASSIGN _ descr:DESCR? {return true;}
  / bexp:BEXP _ descr:DESCR? {return bexp;}

ASSIGN "Assignment"
  = id:ID _ '=' _ exp:EXP {addId(thisParser, id, exp);}
  / id:FILEID _ '=' _ set:FILEREGEX {addFileRegex(thisParser, id, set);}

ID "ID"
  = '<' name:STR '>' {return name;}

FILEID "File ID"
  = '<<' name:STR '>>' {return "<<" + name + ">>";}

EXP "Expression"
  = set:SET {return set;}
  / bexp:BEXP {return bexp;}
  / id:ID {return resolveId(thisParser, id);}

BEXP "Boolean Expression"
  = head:BTERM tail:(_ (OR / AND) _ BTERM)* {
       return tail.reduce(function(result, element) {
        if(element[1] == "||") {
            return result || element[3];
        }
        if(element[1] == "&&") {
            return result && element[3];
        }
      }, head);
   }


BTERM "Boolean Term"
  = left:ELEM _ EQUALS _ right:ELEM {return left == right;}
  / left:SET _ EQUALS _ right:SET {return EQUALS(left, right);}
  / left:SET _ SUBSET _ right:SET {return SUBSET(left, right);}
  / elem:ELEM _ EXISTS _ set:SET {return EXISTS(elem, set);}
  / '[' manbool:MANBOOL '_' script:SCRIPT ']' {return resolveSymbol(thisParser, manbool + '_' + script);}
  / '(' _ bexp:BEXP _ ')' {return bexp;}
  / NOT _ bexp:BEXP {return !bexp;}
  / id:ID _ op:(MATCHESALL / ANYMATCHES)? _ fileidlist:FILEIDLIST? {
      if(fileidlist == null){
        return resolveId(thisParser, id);
      }
      else{
        if(op === "~matchesall"){
          return setAllMatches(resolveId(thisParser, id), fileidlist);
        } else {
          return setAnyMatches(resolveId(thisParser, id), fileidlist);
        }
      }
    }
  / set:SET _ (MATCHESALL / ANYMATCHES) _ fileidlist:FILEIDLIST {
      if(op === "~matchesall"){
        return setAllMatches(set, fileidlist);
      } else {
        return setAnyMatches(set, fileidlist);
      }
  }

SET "Set"
  = head:STERM tail:(_ (UNION / INTERSECT / SUBTRACT) _ STERM)* {
       return tail.reduce(function(result, element) {
        if(element[1] == "~union") return UNION(result, element[3]);
        if(element[1] == "~intersect") return INTERSECT(result, element[3]);
        if(element[1] == "~subtract") return SUBTRACT(result, element[3]);
      }, head);
   }

STERM "Set Term"
  = '[' manset:MANSET '_' script:SCRIPT ']' {return resolveSymbol(thisParser, manset + '_' + script);}
  / '{' _ head:ELEM tail:(_ (',') _ ELEM)* _ '}' {
      let list = new Set([head]);
      for(let i = 0; i < tail.length; i++){
          list.add(tail[i][3])
      }
      return list;
  }
  / id:ID {return resolveId(thisParser, id);}
  / '{}' {return new Set();}
  / '(' _ set:SET _ ')' {return set;}  

FILEIDLIST "File ID List"
  = '[' _ head:FILEID tail:(_ (',') _ FILEID)* _ ']' {
      let list = [head];
      for(let i = 0; i < tail.length; i++){
          list.push(tail[i][3])
      }
      //console.log(list)
      return list;
  }

MANBOOL "Manifest Boolean"
  = 'successful'
  / 'timedOut'
  / 'euidRoot'
  / 'rgidRoot'
  / 'egidRoot'
  / 'priveledgedExecOutputOverNetwork'
  / 'unpriveledgedExecOutputOverNetwork'

MANSET "Manifest Set"
  = 'metadataRequests'
  / 'metadataMods'
  / 'openRead'
  / 'openWrite'
  / 'filesRead'
  / 'filesWritten'
  / 'filesRenamed'
  / 'filesDeleted'
  / 'filesCreated'
  / 'localHosts'
  / 'localNetworkHosts'
  / 'remoteHosts'
  / 'priveledgedCommands'
  / 'unpriveledgedCommands'
  / 'priveledgedExecFiles'
  / 'unpriveledgedExecFiles'

SCRIPT "Script"
  = 'preinstall'
  / 'install'
  / 'postinstall'
  / 'preuninstall'
  / 'uninstall'
  / 'postuninstall'

EXISTS "Exists"
  = '~exists'

UNION "Union"
  = '~union'

INTERSECT "Intersect"
  = '~intersect'

SUBTRACT "Subtract"
  = '~subtract'

SUBSET "Subset"
  = '~subset'

AND "And"
  = '&&'

OR "Or"
  = '||'

EQUALS "Equals"
  = '=='

NOT "Not"
  = '!'

MATCHESALL "Matches All"
  = '~matchesall'

ANYMATCHES "Any Matches"
  = '~anymatches'

ELEM "Element"
  = "'" str:STR "'" {return str;}

FILEREGEX "File Regex"
  = "'" path:PATH "'" {return path;}

PATH "Path"
  = [a-zA-Z\/\\\!\@\#\$\%\^\&\*\(\)\~\+\=\|\.\?\[\]\-\_0-9]+ {return text();}

STR "String"
  = [a-zA-Z\-\_0-9]+ {return text();}

DESCR "Description"
  = ([\/\/]) _ .* {return text();}

_ 'whitespace' = [ \t\n\r]* { return undefined }