import { describe, it, expect, beforeEach } from "vitest";
import { EdgeMesh } from "../../../src/edge-mesh.js";
import { PerfilPacienteAdapter } from "../../../src/adapters/maloca-salud/patient-profile.js";
import type { PacientePerfil } from "../../../src/adapters/maloca-salud/types.js";
import type { NodoId } from "../../../src/types/index.js";

describe("PerfilPacienteAdapter", () => {
  let mesh: EdgeMesh;
  let adapter: PerfilPacienteAdapter;

  beforeEach(() => {
    mesh = new EdgeMesh({
      nodoId: "nodo-test" as NodoId,
      storageBackend: "mem",
    });
    adapter = new PerfilPacienteAdapter(mesh);
  });

  it("debe registrar un paciente correctamente", async () => {
    const perfil: PacientePerfil = {
      id: "paciente-1",
      nombre: "Juan Perez",
      documento: "123456",
      epsId: "eps-1",
      fechaNacimiento: "1990-01-01",
      historialIds: [],
    };

    await adapter.registerPatient(perfil, mesh.identity);

    const pacientes = mesh.yjsAdapter.getMap("maloca-salud:pacientes");
    expect(pacientes.get("paciente-1")).toEqual(perfil);
  });

  it("debe vincular un médico a un paciente", async () => {
    await adapter.linkDoctor("paciente-1", "medico-1");

    const links = mesh.yjsAdapter.getMap("maloca-salud:links-paciente-medico");
    expect(links.get("paciente-1")).toContain("medico-1");
  });

  it("debe obtener el historial médico (vacío inicialmente)", async () => {
    const historial = await adapter.getMedicalHistory("paciente-1");
    expect(historial).toEqual([]);
  });
});
