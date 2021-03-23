package namespace.exceptions

import data.namespaces

exception[ns] {
    ns := data.namespaces[_]
    glob.match("testdata.**", [], ns)
}
