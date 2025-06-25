// servidor Email API
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
  req.token = token;

  // Exibe o header Authorization no console
  console.log(req.headers['authorization']);

  if (!token) {
    return res.status(401).json({ mensagem: 'Acesso negado', erro: 'Token ausente' });
  }

  // Verifica se o token foi invalidado (usuário fez logout)
  if (tokensInvalidos.includes(token)) {
    return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Token inválido. O usuário está offline ou já fez logout.' });
  }

  jwt.verify(token, JWT_SECRET, (erro, payload) => {
    if (erro) {
      try {
        const payloadDecodificado = jwt.decode(token);
        const idExpulso = parseInt(payloadDecodificado?.id, 10);
    
        if (idExpulso && !isNaN(idExpulso)) {
          usuariosLogados = usuariosLogados.filter(u => u.id !== idExpulso);
        }
      } catch (decodeError) {
        console.warn('Erro ao tentar remover usuário com token inválido:', decodeError);
      }
    
      return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Token expirado ou inválido' });
    }

    const id = parseInt(payload.id, 10);
    if (!Number.isInteger(id) || id < 1 || id > 100000) {
      return res.status(500).json({ mensagem: 'Erro na requisição', erro: 'ID inválido no token' });
    }

    const usuarioDados = usuarios.find(u => u.id === id);
    if (!usuarioDados) {
      return res.status(404).json({ mensagem: 'Erro na requisição', erro: 'Usuário não encontrado' });
    }

    req.usuario = {
      id: id,
      email: usuarioDados.email,
      nome: usuarioDados.nome
    };

    next();
  });
}

function validarCamposUsuario({ nome, email, senha }) {
  const erro = [];

  // Validação do nome
  if (nome !== undefined) {
    if (typeof nome !== 'string' || nome.trim() === '' || nome.length > 255) {
      erro.push('Nome deve ser uma string entre 1 e 255 caracteres.');
    }
  }

  // Validação do email
  if (email !== undefined) {
    const regexEmail = /^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$/;
    if (typeof email !== 'string' || email.trim() === '' || !regexEmail.test(email)) {
      erro.push('Email inválido.');
    }
  }

  // Validação da senha
  if (senha !== undefined) {
    if (typeof senha !== 'string' || senha.length < 8 || senha.length > 20) {
      erro.push('Senha deve ter entre 8 e 20 caracteres.');
    }
  }

  // Rejeita se nenhum campo foi enviado (útil no PUT)
  if (nome === undefined && email === undefined && senha === undefined) {
    erro.push('Envie ao menos um campo para atualizar.');
  }

  return erro;
}

function validarCamposRascunho({ assunto, emailDestinatario, corpo }) {
  const erro = [];

  const assuntoPreenchido = assunto !== undefined && assunto !== null && assunto.toString().trim() !== '';
  const corpoPreenchido = corpo !== undefined && corpo !== null && corpo.toString().trim() !== '';
  const emailPreenchido = emailDestinatario !== undefined && emailDestinatario !== null && emailDestinatario.toString().trim() !== '';

  if (assuntoPreenchido) {
    if (typeof assunto !== 'string' || assunto.length < 1 || assunto.length > 255) {
      erro.push('Assunto deve ter entre 1 e 255 caracteres.');
    }
  }

  if (emailPreenchido) {
    const regexEmail = /^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$/;
    if (typeof emailDestinatario !== 'string' || !regexEmail.test(emailDestinatario)) {
      erro.push('Email do destinatário inválido.');
    }
  }

  if (corpoPreenchido) {
    if (typeof corpo !== 'string') {
      erro.push('Corpo do email deve ser um texto.');
    }
  }
  if (!assuntoPreenchido && !corpoPreenchido && !emailPreenchido) {
    erro.push('Pelo menos um dos campos (assunto, destinatário ou corpo) deve ser preenchido.');
  }

  return erro;
}

function validarCamposEmail({ assunto, emailDestinatario, corpo }) {
  const erro = [];

  if (typeof assunto !== 'string' || assunto.trim().length < 1 || assunto.length > 255) {
    erro.push('Assunto é obrigatório e deve ter entre 1 e 255 caracteres.');
  }

  const regexEmail = /^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$/;
  if (typeof emailDestinatario !== 'string' || !regexEmail.test(emailDestinatario)) {
    erro.push('Email do destinatário é obrigatório e deve ser válido.');
  }

  if (typeof corpo !== 'string' || corpo.trim() === '') {
    erro.push('Corpo do email é obrigatório e deve ser um texto.');
  }

  return erro;
}

// Rotas
// Rotas de usuários
// Cadastro de usuário
app.post('/api/usuarios', async (req, res) => {
  const { nome, email, senha } = req.body;
  const erros = validarCamposUsuario({ nome, email, senha });
  if (erros.length > 0) return res.status(400).json({ 
    mensagem: 'Erro na requisição',
    erro: erros.join('\n') });
  
  //if (!nome || !email || !senha) return res.status(400).json({ erro: 'Preencha todos os campos' });

  const existe = usuarios.find(u => u.email === email);
  if (existe) return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Email já cadastrado' });

  const senha_hash = await bcrypt.hash(senha, 10);

  const id = usuarios.length === 0 
  ? 1 
  : Math.max(...usuarios.map(u => u.id)) + 1;
  
  usuarios.push({ id, nome, email, senha_hash });

  res.status(201).json({ mensagem: 'Sucesso ao cadastrar usuário' });

//  res.status(201).json({ mensagem: 'Sucesso ao cadastrar usuário', usuario: {id: id, nome: nome, email: email } });
});

// Login de usuário
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;
  const usuario = usuarios.find(u => u.email === email);
  if (!usuario) return res.status(404).json({ mensagem: 'Usuário não encontrado' });

  const senha_valida = await bcrypt.compare(senha, usuario.senha_hash);
  if (!senha_valida) return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Senha incorreta' });

//  const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1h' });
//  console.log("Usuários logados:", usuariosLogados); // nao esta na lista

const idUsuario = parseInt(usuario.id);

if (!Number.isInteger(idUsuario) || idUsuario < 1 || idUsuario > 100000) {
  return res.status(500).json({ mensagem: 'Erro interno', erro: 'ID de usuário inválido para o token' });
}

const token = jwt.sign({ id: idUsuario }, JWT_SECRET, { expiresIn: '4h' });
  
// Adiciona usuário logado (se ainda não estiver)
const jaLogado = usuariosLogados.find(u => u.email === usuario.email);
  if (!jaLogado) {
    usuariosLogados.push({
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email
    });
  }
  res.status(200).json({ mensagem: 'Sucesso ao realizar login', token: token});

//  res.status(200).json({ mensagem: 'Sucesso ao realizar login', usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email}, token: token});
});

// Rotas de usuários autenticados
// Logout de usuário
app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token && !tokensInvalidos.includes(token)) {
    tokensInvalidos.push(token);
  }

  try {
    const payloadDecodificado = jwt.decode(token);
    const id = parseInt(payloadDecodificado?.id, 10);

    if (id && !isNaN(id)) {
      usuariosLogados = usuariosLogados.filter(u => u.id !== id);
    }
  } catch (decodeError) {
    console.warn('Falha ao remover usuário de usuariosLogados no logout:', decodeError);
  }

  res.status(200).json({ mensagem: 'Logout realizado com sucesso' });
});

/*app.post('/api/logout', autenticarToken, (req, res) => {
  const token = req.token;

  if (token && !tokensInvalidos.includes(token)) {
    tokensInvalidos.push(token);
  }
  
  usuariosLogados = usuariosLogados.filter(u => u.id !== req.usuario?.id);

  res.status(200).json({ mensagem: 'Logout realizado com sucesso'});
});
*/

// Lista de usuários logados
// Dados do usuário
app.get('/api/usuarios', autenticarToken, (req, res) => {
  const usuario = usuarios.find(u => u.id === req.usuario.id);
  //if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado' });

  res.status(200).json({mensagem: 'Sucesso ao buscar usuario', usuario: { nome: usuario.nome, email: usuario.email } });

  //res.status(200).json({mensagem: 'Sucesso ao buscar usuario', usuario: {id: usuario.id, nome: usuario.nome, email: usuario.email } });
});

// Atualização de dados do usuário
app.put('/api/usuarios', autenticarToken, async (req, res) => {
  const { nome, senha } = req.body;
  
  const erros = validarCamposUsuario({ nome, senha });
  if (erros.length > 0) return res.status(400).json({ 
    mensagem: 'Erro na requisição',
    erro: erros.join('\n') });

  const usuario = usuarios.find(u => u.id === req.usuario.id);
  //if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado' });

  if (nome) usuario.nome = nome;
  if (senha) usuario.senha_hash = await bcrypt.hash(senha, 10);

  res.status(200).json({mensagem: 'Sucesso ao atualizar usuario', usuario: {nome: usuario.nome, email: usuario.email } });
});

// Remoção de usuário
app.delete('/api/usuarios', autenticarToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) tokensInvalidos.push(token);
  usuariosLogados = usuariosLogados.filter(u => u.id !== req.usuario.id);
  usuarios = usuarios.filter(u => u.id !== req.usuario.id);
    // apaga emails que tem relacionamento quando excluir usuario
  //  emails = emails.filter(e => e.remetente_id !== req.usuario.id);
    // apaga racunhos que tem relacionamento quando excluir usuario
  //  rascunhos = rascunhos.filter(r => r.remetente_id !== req.usuario.id);
  res.status(200).json({mensagem: 'Sucesso ao excluir usuario'});
});

// Rotas de rascunhos
// Criação de rascunho
app.post('/api/rascunhos', autenticarToken, (req, res) => {
  const { assunto, emailDestinatario, corpo } = req.body;

  const erros = validarCamposRascunho({ assunto, emailDestinatario, corpo });
  if (erros.length > 0) {
    return res.status(400).json({ mensagem: 'Erro na requisição',
      erro: erros.join('\n')  });
  }

  const rascunhoId = rascunhos.length === 0 
  ? 1 
  : Math.max(...rascunhos.map(u => u.rascunhoId)) + 1;

  const novo = {
    rascunhoId: rascunhoId,
    remetente_id: req.usuario.id,
    assunto: assunto || '',
    emailDestinatario: emailDestinatario || '',
    corpo: corpo || '',
    dataEnvio: new Date().toISOString()
  };

  rascunhos.push(novo);
  res.status(200).json({ mensagem: 'Rascunho criado', rascunho: { 
    rascunhoId: novo.rascunhoId, 
    emailDestinatario: novo.emailDestinatario,
    assunto: novo.assunto, 
    corpo: novo.corpo} });
});

// Listagem de rascunhos
app.get('/api/rascunhos', autenticarToken, (req, res) => {
  const meus = rascunhos.filter(r => r.remetente_id === req.usuario.id);
  //console.log('Rascunhos retornados para:', req.usuario.email, meus);
    const rascunhosFiltrados = meus.map(r => ({
      rascunhoId: r.rascunhoId,
      emailDestinatario: r.emailDestinatario,
      assunto: r.assunto,
      corpo: r.corpo
    }));
  
    res.status(200).json({
      mensagem: 'Rascunhos localizados',
      rascunhos: rascunhosFiltrados
    });
});

// Retorno de rascunho específico
app.get('/api/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const rascunho = rascunhos.find(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);

  if (!rascunho) {
    return res.status(404).json({ mensagem: 'Rascunho não encontrado' });
  }

  res.status(200).json({mensagem: 'Rascunho localizado', rascunho: { 
    rascunhoId: rascunho.rascunhoId, 
    emailDestinatario: rascunho.emailDestinatario,
    assunto: rascunho.assunto, 
    corpo: rascunho.corpo}});
});

// Atualização de rascunho
app.put('/api/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const { assunto, emailDestinatario, corpo } = req.body;

  const erros = validarCamposRascunho({ assunto, emailDestinatario, corpo });
  if (erros.length > 0) {
    return res.status(400).json({ 
      mensagem: 'Erro na requisição',
      erro: erros.join('\n')  });
  }

  const rascunho = rascunhos.find(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);
  if (!rascunho) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  if (assunto) rascunho.assunto = assunto;
  if (emailDestinatario) rascunho.emailDestinatario = emailDestinatario;
  if (corpo) rascunho.corpo = corpo;

  rascunho.dataEnvio = new Date().toISOString(); // Atualiza horário

  res.status(200).json({ mensagem: 'Rascunho salvo com sucesso', rascunho: { 
    rascunhoId: rascunho.rascunhoId, 
    emailDestinatario: rascunho.emailDestinatario,
    assunto: rascunho.assunto, 
    corpo: rascunho.corpo}});
});

// Remoção de rascunho
app.delete('/api/rascunhos/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const index = rascunhos.findIndex(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);

  if (index === -1) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  rascunhos.splice(index, 1);
  res.status(200).json({ mensagem: 'Rascunho deletado com sucesso' });
});

// Rotas de emails
// Envio ou resposta de email
app.post('/api/emails', autenticarToken, (req, res) => {
  //const { rascunho_id, resposta_de_id } = req.body;
  const { assunto, emailDestinatario, corpo } = req.body;
  const erros = validarCamposEmail({ assunto, emailDestinatario, corpo });

  if (erros.length > 0) {
    return res.status(400).json({ 
      mensagem: 'Erro na requisição',
      erro: erros.join('\n')  });
  }

  const email_id = emails.length === 0 
  ? 1 
  : Math.max(...emails.map(u => u.emailId)) + 1;

  const novoEmail = {    
    emailId: email_id,
    remetente_id: req.usuario.id,
    emailRemetente: req.usuario.email,
    emailDestinatario: emailDestinatario,
    assunto: assunto,
    corpo: corpo,
    status: 'enviado',
    dataEnvio: new Date().toISOString(),
    //resposta_de_id: resposta_de_id || null
  };

  emails.push(novoEmail);

  res.status(200).json({ mensagem: 'Novo email enviado com sucesso', email: {
    emailId: novoEmail.emailId, 
    emailDestinatario: novoEmail.emailDestinatario,
    emailRemetente: novoEmail.emailRemetente, 
    status: novoEmail.status,    
    assunto: novoEmail.assunto, 
    corpo: novoEmail.corpo, 
    dataEnvio: new Date(novoEmail.dataEnvio).toLocaleDateString('pt-BR')
    } });
});

// Atualização de email marcar como lido não utilizado
app.put('/api/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const email = emails.find(e => e.emailId === id && e.emailDestinatario === req.usuario.email);
  if (!email) return res.status(404).json({ erro: 'Email não encontrado' });

  email.status = 'lido';
  res.status(200).json({ mensagem: 'Email marcado como lido', email: {
    emailId: email.emailId, emailDestinatario: email.emailDestinatario,
    emailRemetente: email.emailRemetente, status: email.status,
    assunto: email.assunto, corpo: email.corpo, dataEnvio: new Date(email.dataEnvio).toLocaleDateString('pt-BR')
    } });
});

// Envio ou resposta de email//ID id do rascunho
app.post('/api/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const rascunho = rascunhos.find(r => r.rascunhoId === id && r.remetente_id === req.usuario.id);
  if (!rascunho) return res.status(404).json({ erro: 'Rascunho não encontrado' });

  if (!rascunho.emailDestinatario || !rascunho.corpo || !rascunho.assunto) {
    return res.status(400).json({ erro: 'Para enviar, o rascunho deve conter emailDestinatario, assunto e corpo' });
  }

  let corpoFinal = rascunho.corpo;

  const email_id = emails.length === 0 
  ? 1 
  : Math.max(...emails.map(u => u.emailId)) + 1;

  const novoEmail = {    
    emailId: email_id,
    remetente_id: req.usuario.id,
    emailRemetente: req.usuario.email,
    emailDestinatario: rascunho.emailDestinatario,
    assunto: rascunho.assunto,
    corpo: corpoFinal,
    status: 'enviado',
    dataEnvio: new Date().toISOString(),
//    resposta_de_id: resposta_de_id || null
  };

  emails.push(novoEmail);
  rascunhos = rascunhos.filter(r => r.rascunhoId !== id); // detelta o rascunho utilizado de rascunhos

  res.status(200).json({ mensagem: 'Email enviado de rascunho com sucesso', email: {
    emailId: novoEmail.emailId, 
    emailDestinatario: novoEmail.emailDestinatario,
    emailRemetente: novoEmail.emailRemetente, 
    status: novoEmail.status,
    assunto: novoEmail.assunto, 
    corpo: novoEmail.corpo, 
    dataEnvio: new Date(novoEmail.dataEnvio).toLocaleDateString('pt-BR')
    } });
});

// Retorno de email específico e marca como lido
app.get('/api/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const email = emails.find(e => e.emailId === id);

  if (!email) {
    return res.status(404).json({ erro: 'Email não encontrado' });
  } else if (email.emailDestinatario !== req.usuario.email) {
    return res.status(400).json({ mensagem: 'Erro na requisição', erro: 'Você não tem permissão para acessar este email' });  }

  email.status = 'lido';

  res.status(200).json({mensagem: 'Email encontrado', email: {
    emailId: email.emailId, 
    emailDestinatario: email.emailDestinatario,
    emailRemetente: email.emailRemetente, 
    status: email.status,
    assunto: email.assunto, 
    corpo: email.corpo, 
    dataEnvio: new Date(email.dataEnvio).toLocaleDateString('pt-BR')
    }});  
});

// Retorno de todos os emails buscando por token
app.get('/api/emails', autenticarToken, (req, res) => {
  const emailsDoUsuario = emails.filter(e => e.emailRemetente === req.usuario.email || e.emailDestinatario === req.usuario.email);
  
  const emailsRecebidos = emailsDoUsuario.map(e => ({
    emailId: e.emailId, 
    emailDestinatario: e.emailDestinatario,
    emailRemetente: e.emailRemetente, 
    status: e.status,
    assunto: e.assunto, 
    corpo: e.corpo, 
    dataEnvio: new Date(e.dataEnvio).toLocaleDateString('pt-BR')
  }));  
  
  res.status(200).json({ mensagem: 'Emails Encontrados', emails: emailsRecebidos});
});

// Remoção de email
app.delete('/api/emails/:id', autenticarToken, (req, res) => {
  const id = parseInt(req.params.id);
  const index = emails.findIndex(e => e.emailId === id && e.remetente_id === req.usuario.id);

  if (index === -1) return res.status(404).json({ erro: 'Email não encontrado' });

  const emailsCliente = emails.map(e => ({
    emailId: e.emailId, 
    emailDestinatario: e.emailDestinatario,
    emailRemetente: e.emailRemetente, 
    status: e.status,
    assunto: e.assunto, 
    corpo: e.corpo, 
    dataEnvio: new Date(e.dataEnvio).toLocaleDateString('pt-BR')
  }));  

  emails.splice(index, 1);
  res.status(200).json({ mensagem: 'Email removido com sucesso', emails: emailsCliente });
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
app.listen(22777, () => console.log('Servidor rodando na porta 22777'));

const path = require('path');

// Servir arquivos estáticos (como admin.html e style.css)
app.use(express.static(path.join(__dirname, '../public')));
