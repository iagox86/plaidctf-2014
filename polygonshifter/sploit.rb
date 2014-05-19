require 'httparty'

login = HTTParty.get('http://54.204.80.192/example').body
login = login.split(/\n/).join('')

login = login.gsub(/.*action="/, '')
login = login.gsub(/submit.*/, '')
puts(login)

action = login.gsub(/".*/, '')
username = login.gsub(/.*Username.*?name="/, '').gsub(/".*/, '')
password = login.gsub(/.*Password.*?name="/, '').gsub(/".*/, '')

puts('action = ' + action)
puts('username = ' + username)
puts('password = ' + password)

response = HTTParty.post(
  "http://54.204.80.192" + action,
  :body => {
    username =>'test',
    password =>'test' 
  },
)

puts(response)
