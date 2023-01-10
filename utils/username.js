// Clean username
module.exports = {
	clean: function (username) {
		try {

			return username.toString();
		} catch (e) {
			return;
		}
	}
};