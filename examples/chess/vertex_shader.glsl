#version 330

layout (location = 0) in vec3 a_position;
layout (location = 1) in vec4 a_color;

out vec4 f_color;

void main() {
	f_color = a_color;
	gl_Position = vec4(a_position, 1.0);
}
