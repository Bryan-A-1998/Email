// server/app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'chave_secreta';

let usuarios = [];
let emails = [];
let rascunhos = [];
let tokensInvalidos = [];
let usuariosLogados = [];

// Middleware para autenticação de token
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ erro: 'Token ausente' });
  }

  // Verifica se o token foi invalidado (usuário fez logout)
  if (tokensInvalidos.includes(token)) {
    return res.status(403).json({ erro: 'Token inválido. O usuário está offline ou já fez logout.' });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) {
      return res.status(403).json({ erro: 'Token expirado ou inválido' });
    }

    req.usuario = usuario;
    next();
  });
}

// Rotas
// Rotas de usuários
// Cadastro de usuário
app.post('/usuarios', async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Preencha todos os campos' });

  const existe = usuarios.find(u => u.email === email);
  if (existe) return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Email já cadastrado' });

  const senha_hash = await bcrypt.hash(senha, 10);
  const id = usuarios.length + 1;
  usuarios.push({ id, nome, email, senha_hash });
  res.status(201).json({ mensagem: 'Sucesso ao cadastrar usuário', usuario: {id: id, nome: nome, email: email } });
});

// Login de usuário
app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const usuario = usuarios.find(u => u.email === email);
  if (!usuario) return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Usuário não encontrado' });

  const senha_valida = await bcrypt.compare(senha, usuario.senha_hash);
  if (!senha_valida) return res.status(401).json({ mensagem: 'Erro na requisição', erro: 'Senha incorreta' });

  const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1h' });
  
  // Adiciona usuário logado (se ainda não estiver)
  const jaLogado = usuariosLogados.find(u => u.id === usuario.id);
  if (!jaLogado) {
    usuariosLogados.push({ id: usuario.id, nome: usuario.nome, email: usuario.email });
    console.log("Usuários logados:", usuariosLogados);
  }
  res.status(200).json({ mensagem: 'Sucesso ao realizar login', usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email}, token: token});
});

// Rotas de usuários autenticados
// Logout de usuário
app.post('/logout', autenticarToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) tokensInvalidos.push(token);
  usuariosLogados = usuariosLogados.filter(u => u.id !== req.usuario.id);
  res.status(200).json({ mensagem: 'Logout realizado com sucesso'});
});

// Dados do usuário
app.get('/usuarios', autenticarToken, (req, res) => {
  const usuario = usuarios.find(u => u.id === req.usuario.id);
  if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado' });
  res.status(200).json({mensagem: 'Sucesso ao buscar usuario', usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email } });
});

// Atualização de dados do usuário
app.put('/usuarios', autenticarToken, async (req, res) => {
  const { nome, email, senha } = req.body;
  const usuario = usuarios.find(u => u.id === req.usuario.id);
  if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado' });

  if (nome) usuario.nome = nome;
  if (email) usuario.email = email;
  if (senha) usuario.senha_hash = await bcrypt.hash(senha, 10);

  res.status(200).json({mensagem: 'Sucesso ao salvar usuario', usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email } });
});

// Remoção de usuário
app.delete('/usuarios', autenticarToken, (req, res) => {
  if (token) tokensInvalidos.push(token);
  usuarios = usuarios.filter(u => u.id !== req.usuario.id);
  emails = emails.filter(e => e.remetente_id !== req.usuario.id);
  rascunhos = rascunhos.filter(r => r.remetente_id !== req.usuario.id);
  res.status(200).json({mensagem: 'Sucesso ao excluir usuario'});
});

// Rotas de rascunhos
// Criação de rascunho
app.post('/rascunhos', autenticarToken, (req, res) => {
  const { assunto, emailDestinatario, corpo } = req.body;

  if (!assunto && !emailDestinatario && !corpo) {
    return res.status(400).json({ erro: 'Preencha ao menos um campo (assunto, emailDestinatario ou corpo)' });
  }

  const rascunhoId = rascunhos.length + 1;

  const novo = {
    rascunhoId,
    remetente_id: req.usuario.id,
    assunto: assunto || '',
    emailDestinatario: emailDestinatario || '',
    corpo: corpo || '',
    data_hora: new Date().toISOString()
  };

  rascunhos.push(novo);
  res.status(200).json({ mensagem: 'Rascunho criado', rascunho: novo });
});

// Listagem de rascunhos
app.get('/rascunhos', autenticarToken, (req, res) => {
  const meus = rascunhos.filter(r => r.remetente_id === req.usuario.id);
  res.status(200).json({mensagem: 'Rascunho localizado', rascunhos: meus});
});

// Retorno de rascunho específico
app.get('/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const rascunho = rascunhos.find(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);

  if (!rascunho) {
    return res.status(404).json({ mensagem: 'Rascunho não encontrado' });
  }

  res.status(200).json({mensagem: 'Rascunho localizado', rascunho: rascunho});
});

// Atualização de rascunho
app.put('/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const { assunto, emailDestinatario, corpo } = req.body;

  if (!assunto && !emailDestinatario && !corpo) {
    return res.status(400).json({ erro: 'Informe ao menos um campo para atualizar' });
  }

  const rascunho = rascunhos.find(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);
  if (!rascunho) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  if (assunto) rascunho.assunto = assunto;
  if (emailDestinatario) rascunho.emailDestinatario = emailDestinatario;
  if (corpo) rascunho.corpo = corpo;

  rascunho.data_hora = new Date().toISOString(); // Atualiza horário

  res.status(200).json({ mensagem: 'Rascunho salvo com sucesso', rascunho: rascunho });
});

// Remoção de rascunho
app.delete('/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const index = rascunhos.findIndex(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);

  if (index === -1) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  rascunhos.splice(index, 1);
  res.status(200).json({ mensagem: 'Rascunho deletado com sucesso' });
});

// Rotas de emails
// Envio ou resposta de email
app.post('/emails', autenticarToken, (req, res) => {
  const { rascunho_id, resposta_de_id } = req.body;

  const rascunho = rascunhos.find(r => r.rascunhoId === rascunho_id && r.remetente_id === req.usuario.id);
  if (!rascunho) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  if (!rascunho.emailDestinatario || !rascunho.corpo) {
    return res.status(400).json({ erro: 'Para enviar, o rascunho deve conter emailDestinatario e corpo' });
  }

  let corpoFinal = rascunho.corpo;

  // Se for resposta, buscar o email original
  if (resposta_de_id) {
    const idResposta = parseInt(resposta_de_id);
    console.log("Buscando email original com ID:", idResposta);
    console.log("Usuário logado:", req.usuario.email);

    const emailOriginal = emails.find(e =>
      e.emailId === idResposta &&
      e.emailDestinatario === req.usuario.email // Email precisa ter sido recebido por esse usuário
    );  

    console.log("Email original encontrado?", emailOriginal);

    if (!emailOriginal) return res.status(404).json({ erro: 'Email original para resposta não encontrado' });

    corpoFinal += `\n\n--- Resposta ao email original ---\n${emailOriginal.corpo}`;
  }

  const novoEmail = {
    emailId: emails.length + 1,
    remetente_id: req.usuario.id,
    emailRemetente: req.usuario.email,
    emailDestinatario: rascunho.emailDestinatario,
    assunto: rascunho.assunto || '',
    corpo: corpoFinal,
    status: 'enviado',
    data_hora: new Date().toISOString(),
    resposta_de_id: resposta_de_id || null
  };

  emails.push(novoEmail);
 // rascunhos = rascunhos.filter(r => r.rascunhoId !== rascunho_id); // detelta o rascunho utilizado de rascunhos

  res.status(200).json({ mensagem: 'Email enviado com sucesso', email: novoEmail });
});

// Atualização deemail marcar como lido
app.put('/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const email = emails.find(e => e.emailId === id && e.emailDestinatario === req.usuario.email);
  if (!email) return res.status(404).json({ erro: 'Email não encontrado' });

  email.status = 'lido';
  res.status(200).json({ mensagem: 'Email marcado como lido', email: email });
});


// Retorno de email específico
app.get('/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const email = emails.find(e => e.emailId === id);

  if (!email) {
    return res.status(404).json({ erro: 'Email não encontrado' });
  } else if (email.emailDestinatario !== req.usuario.email) {
    return res.status(403).json({ erro: 'Você não tem permissão para acessar este email' });  }

  res.status(200).json({mensagem: 'Email encontrado', email: email});  
});

// Retorno de todos os emails buscando por token
app.get('/emails', autenticarToken, (req, res) => {
  const emailsDoUsuario = emails.filter(e => e.emailRemetente === req.usuario.email || e.emailDestinatario === req.usuario.email);
  res.status(200).json({ mensagem: 'Emails Encontrados', emails: emailsDoUsuario});
});

// Remoção de email
app.delete('/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const index = emails.findIndex(e => e.emailId === id && e.remetente_id === req.usuario.id);

  if (index === -1) return res.status(404).json({ erro: 'Email não encontrado' });

  emails.splice(index, 1);
  res.status(200).json({ mensagem: 'Email removido com sucesso', emails: emails });
});

// Listagem de emails enviados pelo usuário
app.get('/emails/enviados', autenticarToken, (req, res) => {
  const enviados = emails.filter(e => e.remetente_id === req.usuario.id);
  res.status(200).json({ mensagem: 'Emails enviados pelo usuario', email: enviados});
});

// Listagem de emails recebidos pelo usuário
app.get('/emails/recebidos', autenticarToken, (req, res) => {
  const recebidos = emails.filter(e => e.emailDestinatario === req.usuario.email);
  res.status(200).json({ mensagem: 'Emails recebidos pelo usuario', email: recebidos});
});

// LOGS API ADMIN PARA INTERFACE
// Rota para exibir todos os usuários
app.get('/admin/usuarios', (req, res) => {
  res.json(usuarios);
});

// Rota para exibir todos os rascunhos
app.get('/admin/rascunhos', (req, res) => {
  res.json(rascunhos);
});

// Rota para exibir todos os emails
app.get('/admin/emails', (req, res) => {
  res.json(emails);
});

// Rota para ver tokens inválidos (logout)
app.get('/admin/tokensInvalidos', (req, res) => {
  res.json(tokensInvalidos);
});

// Rota para ver usuários logados
app.get('/admin/logados', (req, res) => {
  res.json(usuariosLogados);
});

// SERVIDOR RODANDO NA PORTA 3000
app.listen(3000, () => console.log('Servidor rodando na porta 3000'));

const path = require('path');

// Servir arquivos estáticos (como admin.html e style.css)
app.use(express.static(path.join(__dirname, '../public')));
