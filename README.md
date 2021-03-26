# Segurança e Confiabilidade

Projeto de Segurança e Confiabilidadeda Faculdade de Ciências 3 ano

# Como compilar

Servidor:

javac src\server\SeiTchizServer.java

Cliente:

javac src\client\SeiTchiz.java

# Testar

Após o código compilado 

O jar foi criado através do eclipse

Pelo Jar:

Servidor:
java -cp bin -Djava.security.manager -Djava.security.policy=server.policy -jar SeiTchizServer.jar 45678

Cliente:
java -cp bin -Djava.security.manager -Djava.security.policy=client.policy -jar SeiTchiz.jar <IP>:<45678> <userID> <userPassword>

Métodos:

follow <userID> -> o userID pode não existir, caso isso aconteça o cliente é notificado

unfollow <userID> -> o userID pode não existir, caso isso aconteça o cliente é notificado

post <photo> -> o photo é suposto ser o path para a foto ou apenas o nome da foto se tiverem na mesma diretoria

wall <nPhotos> -> o nPhotos tem de ser um inteiro obrigatóriamente

like <photoID> -> o photoID tem de ser do tipo User:ID que é o que é devolvido quando é feito o wall

addu <userID> <groupID> -> caso o userID ou o groupID não existam o cliente é notificado ou caso o cliente não faça parte desse grupo

removeu <userID> <groupID> -> caso o userID ou o groupID não existam o cliente é notificado ou caso o cliente não faça parte desse grupo

msg <groupID> <msg> -> Caso o groupID não exista o cliente é notificado, a menssagem pode ter espaços ou seja do tipo: "ola somos o grupo XX"

collect <groupID> -> Caso o groupID não exista o cliente é notificado

history <groupID> -> Caso o groupID não exista o cliente é notificado

O Trabalho está dividido da seguinte forma:
Um ficheiro para cada utilizador que tem a seguinte informação
User:Daniel
Seguidores:
Seguindo:
Fotos:
ID:0
Grupos:ola/0/0,
Owner:ola,
o ID é o ID da foto mais recente, quando for posta uma novo foto o ID é incrementado e a foto fica com esse ID
Na secção dos grupos, cada grupo tem um nome (ola) o ID da ultima mensagem que deu collect e o ID da mensagem de quando entrou no grupo
Os users estão todos agrupados na pasta users

Um ficheiro para cada grupo que tem a seguinte informação
Owner:Daniel
Members:
ID:0
Chat:
Onde o ID é o ID da próxima mensagem

Os grupos estão todos agrupados numa pasta grupos

Cada foto tem o seguinte nome: User:ID
E estão agrupadas na pasta fotos

Relativamente aos ficheiros policy:

Cliente:


dá permissões ao jar e ao que está na pasta bin para ler e escrever em todos os ficheiros e connectar se a um ip:porta especifico

Servidor:

dá permissões ao jar e ao que está na pasta bin para ler e escrever em todos os ficheiros e connectar se a um ip:porta a porta tem de ser no minimo 1024