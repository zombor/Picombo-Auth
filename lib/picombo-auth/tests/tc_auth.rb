require 'test/unit'
require 'yaml'
require 'singleton'
require '/Users/jeremybush/code/picombo.git/lib/core/core'

class TestConfig < Test::Unit::TestCase
	def setup
		$LOAD_PATH.unshift(File.expand_path(Dir.getwd+'../..')+'/')
		$LOAD_PATH.unshift('/Users/jeremybush/code/picombo.git/lib/')
		#$LOAD_PATH.unshift(File.expand_path(Dir.getwd+'../../../application')+'/')
	end

	def test_hash_password
		password = 'foobar'

		# Create the initial password
		hashed_pass = Picombo::Auth.hash_password(password)

		# Now get the salt out of it
		salt = Picombo::Auth.find_salt(hashed_pass)

		# And try and recreate it
		new_hashed_pass = Picombo::Auth.hash_password(password, salt)
		assert_equal(hashed_pass, new_hashed_pass)
	end
end