import { beforeEach, describe, expect, it, vi } from "vitest";
import * as Y from "yjs";
import {
	ChatChannel,
	ExamenCompartido,
	type Pregunta,
	TIPO_CANAL,
	TIPO_MENSAJE_CHAT,
	TIPO_PREGUNTA,
} from "../../src/chat/index.js";
import { YjsAdapter } from "../../src/edge-mesh.js";
import type { NodoId } from "../../src/types/index.js";

describe("ChatChannel", () => {
	let yjsAdapter: YjsAdapter;
	const nodoId = "peer1" as NodoId;
	const canalNombre = "general";

	beforeEach(() => {
		yjsAdapter = new YjsAdapter();
	});

	it("debería inicializarse correctamente", () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		expect(channel.nodoId).toBe(nodoId);
		expect(channel.nombreCanal).toBe(canalNombre);
		expect(channel.tipoCanal).toBe(TIPO_CANAL.PUBLICO);
	});

	it("debería enviar un mensaje", async () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		const texto = "Hola mundo";
		const id = await channel.enviarMensaje(texto);

		expect(id).toBeDefined();
		const historial = await channel.obtenerHistorial();
		expect(historial.length).toBe(1);
		expect(historial[0].text).toBe(texto);
		expect(historial[0].sender).toBe(nodoId);
	});

	it("debería disparar un evento cuando se recibe un mensaje de otro peer", async () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		const mensajeListener = vi.fn();
		channel.addEventListener("mensaje", mensajeListener as EventListener);

		// Simular mensaje de otro peer vía Yjs
		const yjsMensajes = yjsAdapter.getArray(`chat:${canalNombre}:mensajes`);
		const mensajeRemoto = {
			id: "msg-1",
			sender: "peer2",
			text: "Hola desde peer2",
			timestamp: Date.now(),
			type: TIPO_MENSAJE_CHAT.TEXTO,
			canal: canalNombre,
		};

		yjsMensajes.push([mensajeRemoto]);

		// Esperar a que el observador de Yjs se dispare y se procese
		await new Promise((resolve) => setTimeout(resolve, 100));

		expect(mensajeListener).toHaveBeenCalled();
		const event = mensajeListener.mock.calls[0][0] as CustomEvent;
		expect(event.detail.mensaje.text).toBe("Hola desde peer2");
	});

	it("debería manejar la presencia de usuarios", async () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		const conectadoListener = vi.fn();
		channel.addEventListener(
			"usuarioConectado",
			conectadoListener as EventListener,
		);

		await channel.unirseAlCanal();
		expect(channel.obtenerUsuariosConectados()).toContain(nodoId);

		// Simular otro usuario uniéndose
		const yjsUsuarios = yjsAdapter.getArray(`chat:${canalNombre}:usuarios`);
		yjsUsuarios.push(["peer2"]);

		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(conectadoListener).toHaveBeenCalled();
		expect(channel.obtenerUsuariosConectados()).toContain("peer2");

		const desconectadoListener = vi.fn();
		channel.addEventListener(
			"usuarioDesconectado",
			desconectadoListener as EventListener,
		);

		yjsUsuarios.delete(1, 1); // eliminar peer2

		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(desconectadoListener).toHaveBeenCalled();
		expect(channel.obtenerUsuariosConectados()).not.toContain("peer2");
	});

	it("debería obtener historial con límite", async () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		await channel.enviarMensaje("m1");
		await channel.enviarMensaje("m2");
		await channel.enviarMensaje("m3");

		const historial = await channel.obtenerHistorial(2);
		expect(historial.length).toBe(2);
		expect(historial[0].text).toBe("m2");
		expect(historial[1].text).toBe("m3");
	});

	it("debería limpiar el historial", async () => {
		const channel = new ChatChannel(nodoId, canalNombre, yjsAdapter);
		await channel.enviarMensaje("m1");
		await channel.limpiarHistorial();

		const historial = await channel.obtenerHistorial();
		expect(historial.length).toBe(0);
	});
});

describe("ExamenCompartido", () => {
	let yjsAdapter: YjsAdapter;
	const examenId = "exam-123";

	beforeEach(() => {
		yjsAdapter = new YjsAdapter();
	});

	it("debería cargar y obtener preguntas", async () => {
		const examen = new ExamenCompartido(examenId, yjsAdapter);
		const preguntas: Pregunta[] = [
			{
				id: "p1",
				tipo: TIPO_PREGUNTA.OPCION_MULTIPLE,
				enunciado: "¿2+2?",
				puntaje: 1,
				opciones: ["3", "4"],
				respuestaCorrecta: "4",
			},
		];

		await examen.cargarPreguntas(preguntas);
		expect(examen.obtenerPreguntas()).toEqual(preguntas);
	});

	it("debería agregar una pregunta y disparar evento", async () => {
		const examen = new ExamenCompartido(examenId, yjsAdapter);
		const preguntaListener = vi.fn();
		examen.addEventListener(
			"preguntaAgregada",
			preguntaListener as EventListener,
		);

		const nuevaPregunta: Pregunta = {
			id: "p2",
			tipo: TIPO_PREGUNTA.VERDADERO_FALSO,
			enunciado: "¿Es de día?",
			puntaje: 1,
		};
		await examen.agregarPregunta(nuevaPregunta);

		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(preguntaListener).toHaveBeenCalled();
		expect(examen.obtenerPreguntas()).toContainEqual(nuevaPregunta);
	});

	it("debería enviar respuesta y disparar evento", async () => {
		const examen = new ExamenCompartido(examenId, yjsAdapter);
		const respuestaListener = vi.fn();
		examen.addEventListener(
			"respuestaNueva",
			respuestaListener as EventListener,
		);

		await examen.enviarRespuesta("estudiante1", "p1", "4");

		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(respuestaListener).toHaveBeenCalled();
		const event = respuestaListener.mock.calls[0][0] as CustomEvent;
		expect(event.detail.estudianteId).toBe("estudiante1");
		expect(event.detail.preguntaId).toBe("p1");
		expect(event.detail.respuesta).toBe("4");

		const respuestas =
			await examen.obtenerRespuestasDeEstudiante("estudiante1");
		expect(respuestas.get("p1")).toBe("4");
	});

	it("debería iniciar y finalizar el examen", async () => {
		const examen = new ExamenCompartido(examenId, yjsAdapter);
		const inicioListener = vi.fn();
		const finListener = vi.fn();

		examen.addEventListener("examenIniciado", inicioListener as EventListener);
		examen.addEventListener("examenFinalizado", finListener as EventListener);

		await examen.iniciarExamen();
		expect(inicioListener).toHaveBeenCalled();
		let estado = await examen.obtenerEstado();
		expect(estado.estado).toBe("iniciado");

		await examen.finalizarExamen();
		expect(finListener).toHaveBeenCalled();
		estado = await examen.obtenerEstado();
		expect(estado.estado).toBe("finalizado");
	});
});
