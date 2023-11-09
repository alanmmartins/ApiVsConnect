package com.senai.apivsconnect.controllers;

import com.senai.apivsconnect.dtos.LoginDto;
import com.senai.apivsconnect.dtos.TokenDto;
import com.senai.apivsconnect.models.UsuarioModel;
import com.senai.apivsconnect.services.TokenService;
import jakarta.validation.Valid;
import lombok.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager; // Injeção de dependência do AuthenticationManager

    @Autowired
    private TokenService tokenService; // Injeção de dependência do TokenService

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid LoginDto dadosLogin) {
        // Cria um objeto UsernamePasswordAuthenticationToken com as informações de login do usuário
        var usernamePassword = new UsernamePasswordAuthenticationToken(dadosLogin.email(), dadosLogin.senha());

        // Chama o AuthenticationManager para autenticar o usuário com as credenciais fornecidas
        var auth = authenticationManager.authenticate(usernamePassword);

        // Gera um token JWT com base no usuário autenticado
        var token = tokenService.gerarToken((UsuarioModel) auth.getPrincipal());

        // Retorna uma resposta de status OK com a mensagem "Logado"
        return ResponseEntity.status(HttpStatus.OK).body(new TokenDto(token));
    }
}
