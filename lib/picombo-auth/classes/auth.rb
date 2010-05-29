# Picombo Auth Class
#
# Author:: Jeremy Bush
# Copyright:: Copyright (c) 2009 Jeremy Bush
# License:: See LICENSE

require 'digest/sha1'

module Picombo
	class Auth
		include Singleton

		def login(user, password)
			field_name = Picombo::Models::User.name_field

			user = Picombo::Models::User.first(field_name => user, :password => Picombo::Auth.hash_password(password))

			if user
				# set the session as logged in
				Picombo::Session.instance.set('loggedin', true)
				Picombo::Session.instance.set('user', user)

				return true
			end

			false
		end

		def logout
			Picombo::Session.instance.unset('loggedin')
			Picombo::Session.instance.unset('user')
		end

		# gets the user from the session
		def user
			return nil if ! logged_in?

			Picombo::Session.instance.get('user')
		end

		def self.logged_in?
			! Picombo::Session.instance.get('loggedin').nil?
		end

		def self.hash_password(password, salt = false)
			Digest::SHA1.hexdigest(password)
		end
	end
end