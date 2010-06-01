# Picombo Auth Class
#
# Author:: Jeremy Bush
# Copyright:: Copyright (c) 2009 Jeremy Bush
# License:: See LICENSE

require 'digest/sha1'

module Picombo
	# == Auth Class
	#
	# Performs user Authentication
	class Auth
		include Singleton

		# Performs a user login
		def login(user, password)
			field_name = Picombo::Models::User.name_field

			user = Picombo::Models::User.first(field_name => user)

			if user
				# Find the salt from the existing password, and compare with the provided pass
				salt = Picombo::Auth.find_salt(user.password)
				if Picombo::Auth.hash_password(password, salt) == user.password
					# set the session as logged in
					Picombo::Session.instance.set('loggedin', true)
					Picombo::Session.instance.set('user', user)

					return true
				end
			end

			false
		end

		# Logs a user out
		def logout
			Picombo::Session.instance.unset('loggedin')
			Picombo::Session.instance.unset('user')
		end

		# gets the user from the session
		def user
			return nil if ! logged_in?

			Picombo::Session.instance.get('user')
		end

		# Determines if the current user is logged in
		def self.logged_in?
			! Picombo::Session.instance.get('loggedin').nil?
		end

		# Hashes a password using a secure salt
		def self.hash_password(password, salt = false)
			salt_pattern = Picombo::Config.get('auth.salt_pattern')

			# Create a salt seed, same length as the number of salt offsets
			salt = Digest::SHA1.hexdigest((1..8).map{|i| ('a'..'z').to_a[rand(26)]}.join)[0..salt_pattern.length - 1] if ! salt

			# Password hash that the salt will be inserted into
			hash = Digest::SHA1.hexdigest(salt+password)

			# Change salt into an array
			salt = salt.split('')

			# Returned password
			password = ''

			# Used to calculate the length of splits
			last_offset = 0

			salt_pattern.each do |offset|
				# Split a new part of the hash off
				part = hash[0..(offset - last_offset)-1]

				# Cut the current part out of the hash
				hash = hash[(offset - last_offset)..hash.length]

				# Add the part to the password, appending the salt character
				password+=part+salt.shift

				last_offset = offset
			end

			password+hash
		end

		# Finds the salt of a salted password
		def self.find_salt(password)
			salt = ''
			salt_pattern = Picombo::Config.get('auth.salt_pattern')

			salt_pattern.each_index do |i|
				# Find salt characters, take a good long look...
				salt+=password[salt_pattern[i]+i, 1].to_s
			end

			salt
		end
	end
end