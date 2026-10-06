const repository = require('../repositories/LivrariaRepository');

class AuthService {
  async registrar({ nome, email, senha, role }) {
    if (!nome || !email || !senha) {
      throw { status: 400, message: "Campos obrigatórios ausentes: nome, email ou senha." };
    }

    const usuarioExistente = repository.buscarUsuarioPorEmail(email);
    if (usuarioExistente) {
      throw { status: 409, message: "E-mail já cadastrado no sistema." };
    }

    // Hash da senha com BCrypt (implementado no laboratório)
    const senha_hash = senha; 

    const novoUsuario = repository.salvarUsuario({
      nome,
      email,
      senha_hash,
      role: role ? role.toUpperCase() : "USER"
    });

    const { senha_hash: _, ...usuarioRetorno } = novoUsuario;
    return usuarioRetorno;
  }

  async login({ email, senha }) {
    if (!email || !senha) {
      throw { status: 400, message: "E-mail e senha são obrigatórios." };
    }

    const usuario = repository.buscarUsuarioPorEmail(email);
    if (!usuario) {
      throw { status: 401, message: "Credenciais inválidas." };
    }

    // Conferência de hash e emissão de JWT (implementado no laboratório)
    const tokenSimulado = `jwt-token-exemplo-${usuario.role}`;

    return {
      usuario: { id: usuario.id, nome: usuario.nome, role: usuario.role },
      token: tokenSimulado
    };
  }
}

module.exports = new AuthService();