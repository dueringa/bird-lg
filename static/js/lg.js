const noArgReqs = ["summary"];

function lg_query(selector) {
    return document.querySelectorAll(selector);
}

/**
 * @returns {Node} This is probably a lie, but I want IntelliSense in VScode
 */
function lg_query_single(selector) {
    return document.querySelector(selector);
}

function lg_query_do(selector, fun) {
    lg_query(selector).forEach((ele) => { fun(ele); })
}

function lg_hide(selector) {
    lg_query_do(selector, (element) => {
        element.style.display = "none";
    });
}

function lg_show(selector) {
    lg_query_do(selector, (element) => {
        element.style.display = "";
    });
}

function change_url(loc) {
    lg_show(".progress");
    document.location = loc;
}

function reload() {
    loc = "/" + request_type + "/" + hosts + "/" + proto;
    if (!noArgReqs.includes(request_type)) {
        if (request_args != undefined && request_args != "") {
            loc = loc + "?q=" + encodeURIComponent(request_args);
            change_url(loc)
        }
    } else {
        change_url(loc)
    }
}

function update_view() {
    if (noArgReqs.includes(request_type)) {
        lg_hide(".navbar-search");
    }
    else {
        lg_show(".navbar-search");
    }

    lg_query_do(".navbar li", (ele) => { ele.classList.remove("active"); })

    const node_proto = lg_query_single(".proto a#" + proto);
    if (node_proto) { node_proto.parentElement.classList.add('active'); }
    const node_hosts = lg_query_single(".hosts a[id='" + hosts + "']")
    if (node_hosts) { node_hosts.parentElement.classList.add('active') }
    const node_request = lg_query_single(".request_type a#" + request_type);
    if (node_request) { node_request.parentElement.classList.add('active') }

    command = lg_query_single(".request_type a#" + request_type).textContent.split("...");
    // first element
    let requestNode = lg_query_single(".request_type a");
    requestNode.innerHTML = command[0] + '<b class="caret"></b>';
    let navbar_eles = lg_query(".navbar li");
    let last_navbar_element = navbar_eles[navbar_eles.length - 1];
    if (command[1] != undefined) {
        last_navbar_element.innerHTML = "&nbsp;&nbsp;" + command[1];
    } else {
        last_navbar_element.innerHTML = "";
    }

    let rqa_ele = lg_query_single(".request_args")
    request_args = rqa_ele.value;
    rqa_ele.focus();
    rqa_ele.select();
}
var ready = (callback) => {
    if (document.readyState !== "loading") { callback(); }
    else { document.addEventListener("DOMContentLoaded", callback); }
}

ready(() => {
    lg_query_do(".history a", (ele) => ele.addEventListener("click", (event) => {
        event.preventDefault();
        change_url(ele.href);
    }));

    lg_query_single(".modal .modal-footer .btn").addEventListener("click", (event) => {
        // This is a bootstrap thing
        $(".modal").modal('hide');
    });

    lg_query_do("a.whois", (ele) => ele.addEventListener("click", (event) => {
        event.preventDefault();
        link = ele.getAttribute('href');
        $.getJSON(link, function (data) {
            lg_query_single(".modal h3").textContent = data.title;

            let whois_content = lg_query_single(".modal .modal-body > p");
            whois_content.style.whiteSpace = "pre-line";
            whois_content.textContent = data.output;
            $(".modal").modal('show');
        });
    }));

    lg_query_do(".history a", (ele) => ele.addEventListener("click", () => {
        lg_query_do(".history li", (ele) => { ele.classList.remove("active"); })
        ele.parentElement.classList.add("active")
    }));


    lg_query_do(".hosts a", (ele) => ele.addEventListener("click", () => {
        hosts = ele.id
        update_view();
        reload();
    }));
    lg_query_do(".proto a", (ele) => ele.addEventListener("click", () => {
        proto = ele.id;
        update_view();
        reload();
    }));
    lg_query_do(".request_type ul a", (ele) => ele.addEventListener("click", () => {
        if (request_type.split("_")[0] != ele.id.split("_")[0]) {
            request_args = ""
            lg_query_do(".request_args", ele => ele.value = "")
        }
        request_type = ele.id;
        update_view();
        reload();
    }));
    $("form").submit(function () {
        update_view();
        reload();
    });
    lg_query_single(".request_args").value = request_args;
    update_view();

    t = $('.table-summary')
    if (t) t.dataTable({
        "bPaginate": false,
    });

});


