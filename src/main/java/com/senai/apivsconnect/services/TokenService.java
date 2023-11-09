package com.senai.apivsconnect.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.senai.apivsconnect.models.UsuarioModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;


    public String gerarToken(UsuarioModel usuario){
        try{
            // Cria um objeto Algorithm com o algoritmo HMAC256 e a chave secreta 'secret'
            Algorithm algoritimo = Algorithm.HMAC256(secret);

            // Cria um objeto JWT e começa a construção do token
            String token = JWT.create()

                    .withIssuer("api-vsconnect")// Define o emissor como 'api-vsconnect'
                    .withSubject(usuario.getEmail())// Define o assunto como o email do usuário
                    .withExpiresAt(gerarVlidadeToken()) // Define a data de expiração do token
                    .sign(algoritimo);// Assina o token com o algoritmo e a chave secreta

            return token;

        }catch (JWTCreationException exception){
            // Em caso de erro ao criar o token, lança uma exceção com a mensagem de erro
            throw new RuntimeException("Error creating",exception);

        }
    }
    public String validarToken(String token){
        try {
            Algorithm algoritimo = Algorithm.HMAC256(secret);
            return JWT.require(algoritimo)
                    .withIssuer("api-vsconnect")
                    .build()
                    .verify(token)
                    .getSubject();

        }catch (JWTCreationException exception){
            throw new RuntimeException(exception);
        }
    }

    private Instant gerarVlidadeToken(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }


}
