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
	lg_query(selector).forEach(ele => { fun(ele); })
}

function lg_hide(selector) {
	lg_query_do(selector, element => {
		element.style.display = "none";
	});
}

function lg_show(selector) {
	lg_query_do(selector, element => {
		element.style.display = "";
	});
}

$(window).unload(function () {
	lg_show(".progress");
});

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
	if (noArgReqs.includes(request_type))
		lg_hide(".navbar-search");
	else
		lg_show(".navbar-search");

	lg_query_do(".navbar li", ele => { ele.classList.remove("active"); })

	const node_proto = lg_query_single(".proto a#" + proto);
	if (node_proto)
		node_proto.parentElement.classList.add('active');
	const node_hosts = lg_query_single(".hosts a[id='" + hosts + "']")
	if (node_hosts)
		node_hosts.parentElement.classList.add('active')
	const node_request = lg_query_single(".request_type a#" + request_type);
	if (node_request)
		node_request.parentElement.classList.add('active')

	command = $(".request_type a#" + request_type).text().split("...");
	$(".request_type a:first").html(command[0] + '<b class="caret"></b>');
	if (command[1] != undefined) {
		$(".navbar li:last").html("&nbsp;&nbsp;" + command[1]);
	} else {
		$(".navbar li:last").html("");
	}

	request_args = $(".request_args").val();
	$(".request_args").focus();
	$(".request_args").select();
}
$(function () {
	$(".history a").click(function (event) {
		event.preventDefault();
		change_url(this.href)
	});
	$(".modal .modal-footer .btn").click(function () {
		$(".modal").modal('hide');
	});
	$("a.whois").click(function (event) {
		event.preventDefault();
		link = $(this).attr('href');
		$.getJSON(link, function (data) {
			$(".modal h3").html(data.title);
			$(".modal .modal-body > p").css("white-space", "pre-line").text(data.output);
			$(".modal").modal('show');
		});
	});

	$(".history a").click(function () {
		lg_query_do(".history li", ele => { ele.classList.remove("active"); })
		$(this).parent().addClass("active")
	});


	$(".hosts a").click(function () {
		hosts = $(this).attr('id');
		update_view();
		reload();
	});
	$(".proto a").click(function () {
		proto = $(this).attr('id');
		update_view();
		reload();
	});
	$(".request_type ul a").click(function () {
		if (request_type.split("_")[0] != $(this).attr('id').split("_")[0]) {
			request_args = ""
			$(".request_args").val("");
		}
		request_type = $(this).attr('id');
		update_view();
		reload();
	});
	$("form").submit(function () {
		update_view();
		reload();
	});
	$('.request_args').val(request_args);
	update_view();

	t = $('.table-summary')
	if (t) t.dataTable({
		"bPaginate": false,
	});

});


