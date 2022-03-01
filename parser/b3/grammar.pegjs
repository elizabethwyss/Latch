line "line"
  = error_line / alert_line / exit_line / signal_line / stopped_line / syscall_line

// add one for strace error

error_line "error_line"
  = error:error {
      return {
        error: error,
        type: 'ERROR'
      }
    }

alert_line "alert_line"
  = pid:pid? alert:alert {
      return {
        pid: pid,
        alert: alert,
        type: 'ALERT'
      }
    }

exit_line "exit line"
  = time:time? _ "+++ exited with" _ [0-9]+ _ "+++" {return undefined;}

signal_line "signal line"
  = time:time? _ "---" _ flag _ data_structure _ "---" {return undefined;}

stopped_line "stopped_line"
  = pid:pid? notice:stop_notice {
      return {
        pid: pid,
        alert: notice,
        type: 'STOPPED'
      }
    }

syscall_line "syscall_line"
  = time:time? pid:pid?
    syscall:syscall args:arguments_list result:result timing:timing? {
    return {
        time: time,
        syscall: syscall,
        args: args,
        result: result,
        pid: pid,
        type: 'SYSCALL'
    }
  }

syscall "syscall"
  = _ value:([_a-zA-Z0-9'"]+) { return value.join(''); }

data_structure "data_structure"
  = socket_address_length_enclosed / socket_address_length /
    array /
    nested_struct / struct /
    bitwise_array /
    ip_address / address / ellipsis /
    socket /
    boolean /
    function_call /
    decodedfds / int /
    string /
    struct_property /
    null /
    flags_alternate / flags / flag

comment "comment"
  = "/*" (!"*/" .)* "*/"

boolean "boolean"
  = [A-Z]+ '(' [a-z] ')' _ '&&' _ [A-Z]+ '(' [a-z] ')' _ '==' _ int

array "array"
  = '['
    values:array_elements
  ']'
  { return values !== null ? values : []; }

array_elements "array_elements"
  = (
    head:data_structure
    tail:(',' _ value:data_structure { return value; })*
    { return [head].concat(tail); }
  )?

bitwise_array "bitwise_array"
  = values:(
    operator:([~^]) '['
    head:(value:bitwise_array_element { return value.join(''); })
    tail:(',' _ value:bitwise_array_element { return value.join(''); })*
      {
        return {
          operator:operator,
          elements: [head].concat(tail)
        };
      }
    )?
  ']'
  { return values !== null ? values : []; }

bitwise_array_element "bitwise_array_element"
  = _ array_elements:flags _ { return array_elements; }

flag "flag" = _ value:[_A-Z0-9]+ _ { return value.join(''); }

flags "flags"
  = values:(
    head:flag
    tail:(('|' / 'or') _ value:(address / flag) { return value; })*
      { return [head].concat(tail); }
    )?
  { return values !== null ? values : []; }

flags_alternate "flags_alternate"
  = operator:([~^])? '['
  values:(
    head:flag
    tail:(_ value:flag { return value; })*
      {
        var elements = [head].concat(tail);

        if(operator) {
          return {
            operator: operator,
            elements: elements
          }
        }

        return elements;
      }
    )?
  ']'
  { return values !== null ? values : []; }

nested_struct "nested struct"
  = '{'
    values:(
      head:struct
      tail:(',' _ value:data_structure { return value })? {
        return [head].concat([tail]);
      }
    )?
  '}' {
    return values;
  }

struct "struct"
  = '{' _
      values:(
        head:data_structure
        tail:((',' / ' ') _ value:(comment / data_structure) { return value })*
      {
        var result = {};

        [head].concat(tail).forEach(function(element) {
          if(element){
            if(!element.hasOwnProperty('name') || !element.hasOwnProperty('value')) {
              result[element] = element;
            } else {
              result[element.name] = element.value;
            }
          }
          
        });

        return result;
      })
    _ '}' _ timeComment?
    {
      return values !== null ? values : [];
    }

struct_property "struct_property"
  = key:(key / capitalised_key) _ ("=")? _ value:(function_call / quoted_value / arithmetic_expression / data_structure / basic_value)? {
      if(typeof value !== 'undefined' && value !== '') {
        return {name: key, value: value}
      }

      return {name: key, value: key};
    }

key "key"
  = value:[_a-z0-9]+ { return value.join(''); }

capitalised_key "capitalised key"
  = value:([A-Z][_a-z0-9]+) {
      var flattened = [].concat.apply([], value);
      return flattened.join('');
    }

arguments_list "arguments_list"
  = '(' _ values:(
    head:data_structure comment?
    tail:(("," / " ") _ value:(arguments_list_abbreviation / (data_structure comment?)) { return value; })*
      {
        // if both the head and tail are empty arrays, don't return an array in an array
        if ((tail === null || tail.length <= 0) && (head === null || head.length <= 0)) {
          return [];
        }

        return [head].concat(tail);
      }
    )?
    _ ')'
  {
    return values !== null ? values : [];
  }

arguments_list_abbreviation "arguments_list_abbreviation"
  = ("/*" _ [0-9]+ _ ("vars" / "entries") _ "*/") { return '...'; }

int = [-0-9]+ { return parseInt(text()); }

ip_address "ip address"
  = ipv4 /
    ipv6

ipv6 "ipv6"
  = ip:ip6 {return {ip}}

ip6 "ip6"
  = ("[")? ip:(([0-9a-f]*(':' / '::'))+[0-9a-f]*) ("]:"[0-9]+)? {
    return ip.join('').replace(/,/g,'');
  }

ipv4 "ipv4"
  = ip:([0-9]+ "." [0-9]+ "." [0-9]+ "." [0-9]+) port:(":" ([0-9]+))? { 
    if(port != null){
      return {
        "ip": ip.join('').replace(/,/g, ''),
        "port": port.join('').substring(1, port.join('').length).replace(/,/g, '')
      }
    }
    else{
      return {
        "ip": ip.join('').replace(/,/g, '')
      }
    }
  }

address "address" = '0x' value:([0-9a-fA-F]*) { return parseInt(value.join(''), 16) }

null "null" = _ "NULL" _ { return null; }

// string processing borrowed from https://github.com/pegjs/pegjs/blob/master/examples/json.pegjs
string "string"
  = _ quotation_mark chars:char* quotation_mark ellipsis? { return chars.join(""); }

socket "socket"
  = "@" path:string { return path }

socket_address_length_enclosed "socket_address_length_enclosed"
  = "[" data:socket_address_length "]" { return data }

socket_address_length "socket_address_length"
  = ulen:([0-9]+) "->" rlen:([0-9]+) {
    return {
      ulen: parseInt(ulen.join('')),
      rlen: parseInt(rlen.join(''))
    }
  }

char "char"
  = unescaped
  / escape
    sequence:(
        '"'
      /  "'"
      / "\\"
      / "/"
      / digits:digit+ { return ["\\"].concat(digits).join('') }
      / value:[a-zA-Z] { return "\\" + value }
    )
    { return sequence; }

escape "escape"
  = "\\"

quotation_mark "quotation_mark"
  = '"' / '"'

unescaped "unescaped"
  = [^\0-\x1F\x22\x5C]

digit "digit" = [0-9]
hex_digit = hex:([0][xX][0-9a-fA-F]+) {return parseInt(hex.join('').replace(/,/g, ''))}

// unquoted values should either start with a lowercase letter or number, or else be considered a flag
basic_value "basic_value"
  = value:([_a-z0-9][_a-zA-Z0-9]+) {
      var flattened = [].concat.apply([], value);
      return flattened.join('');
    }

quoted_value "quoted_value" = value:string { return value; }
function_call "function_call"
  = values:(
  		function_name:basic_value
      _ "(" params:array_elements
        ([^\)])*
      ")" { return {function: function_name, params: params} }
    )

arithmetic_expression "arithmetic_expression" = [-0-9]+ _ [+-/*] _ [-0-9]+

result "result"
  = _ '=' _ 
    res:(hex_digit / decodedfds /
    address fileStatusFlags? /
    normalResult /
    anything) anything? {
      return res;
    }

normalResult "normal result"
  = res:int _ flag:(flag?) _ end:(anything?) {
    if(flag != null){
      if(end != null){
        return {
          "result": res,
          "flag": flag,
          "end": end
        }
      }
      else {
        return {
          "result": res,
          "flag": flag,
        }
      }
    }
    else{
      if(end != null){
        return {
          "result": res,
          "end": end
        }
      }
      else {
        return {"result": res}
      }
    }
  }

anything "anything" 
  = _ (.)+ {
    return {"result": text()};
  }

timing "timing" = _ '<' value:([\.\-0-9]+) '>' _ { return Number(value.join('')); }

pid "pid" = ('[pid' _)? _ value:([0-9]+) _ (']')? _ { return Number(value.join('')); }

ellipsis "ellipsis" = _ '...' _ { return undefined }

alert "alert" = "+++" _ message:[^\+]+ _ "+++" { return message.join('').trim() }

stop_notice "stop_notice" = "---" _ signal:flag _ data:data_structure _ "---" { return { signal: signal, data: data } }

error "error" = "strace:" _ error:(.+) { return error.join('').trim() }

_ 'whitespace' = [ \t\n\r]* { return undefined }

fileStatusFlags "file status flags"
  = _ '(flags' _ flags _ ')' 

timeComment "time comment"
  = _ '/*' _ [0-9]+ '-' [0-9]+ '-' [0-9]+ 'T' [0-9]+ ':' [0-9]+ ':' [0-9]+ ('.' [0-9]+)? '-' [0-9]+ _ '*/'

time "time"
  = _ time:([0-9]+ '.' [0-9]+) {return parseFloat(time.join('').replace(/,/g, ''));}

decodedfds "decoded file descriptor" 
  = fd:int 
    descr:(ipcconnection /
    tcpudpconnection /
    pipe /
    symbolicLink /
    filepath) {
      return {
        "fd": fd,
        "description": descr
      }
    }

tcpudpconnection "tcp/udp connection"
  = "<" type:([a-zA-Z0-9]+) ":[" from:(ip_address) "->" to:(ip_address) "]>" {
    return {
      "connectionType": type.join('').replace(/,/g, ''),
      "from": from,
      "to": to
    }
  }

ipcconnection "ipc connection"
  = "<" type:([a-zA-Z]+) ":[" from:([0-9]+) "->" to:([0-9]+) "]>" {
    return {
      "connectionType": type.join('').replace(/,/g, ''),
      "from": from.join('').replace(/,/g, ''),
      "to": to.join('').replace(/,/g, '')
    }
  }

pipe "pipe"
  = "<" type:([a-zA-Z]+) ":[" id:([0-9]+) "]>" {
    return {
      "connectionType": type.join('').replace(/,/g, ''),
      "id": id.join('').replace(/,/g, '')
    }
  }

symbolicLink "symbolic link"
  = "<" type:([a-zA-Z]+) ':[' inode:(int / [a-zA-Z]+ ':' int / "eventpoll") ']>' {
    return {
      "type": type.join('').replace(/,/g, ''),
      "inode": inode.join('').replace(/,/g, '')
    }
  }

filepath "file path" 
  ="<" name:(([/a-zA-Z.:!^\[\]()%\'@#$+=\\\-_0-9~ ])+) extra:("<char" _ [0-9]+ ":" [0-9]+">")? ">" {
    return {"path": name.join('')};
  }
