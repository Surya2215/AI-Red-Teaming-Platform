from garak.generators.rest import RestGenerator

g = RestGenerator(
    uri="http://ec2-13-201-121-27.ap-south-1.compute.amazonaws.com:8001/chat"
)

print(g.uri)